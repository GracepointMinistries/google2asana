package main

import (
	"database/sql"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"strings"
	"unicode"

	"github.com/fitzboy/asana/v1"
	_ "github.com/go-sql-driver/mysql"
	"github.com/kelseyhightower/envconfig"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/jwt"
	"google.golang.org/api/admin/directory/v1"
	"gopkg.in/yaml.v2"
)

type Config struct {

	// the API key given by Asana
	AsanaPersonalAccessToken string `yaml:"asana_personal_access_token" envconfig:"asana_personal_access_token"`
	// the Workspace name within Asana (ie the "org name")
	WorkspaceName string `yaml:"workspace_name" envconfig:"workspace_name"`

	// user/password/db to use for mysql DB that has the asanaSyncLog
	MysqlConfig *string `yaml:"mysql_config" envconfig:"mysql_config"`

	// these are the settings for Google oauth2 to work
	GooglePemPath    *string `yaml:"google_pem_path" envconfig:"google_pem_path"`
	GooglePemValue   string  `yaml:"google_pem_value" envconfig:"google_pem_value"`
	GooglePemEmail   string  `yaml:"google_pem_email" envconfig:"google_pem_email"`
	GooglePemSubject string  `yaml:"google_pem_subject" envconfig:"google_pem_subject"`

	// in google groups, if you want to exclude users with a certain prefix, put it here
	EmailPrefixFilter string `yaml:"email_prefix_filter" envconfig:"email_prefix_filter"`

	// a google group alias that has members you wish to be admin on ALL asana teams
	AdminAlias string `yaml:"admin_alias" envconfig:"admin_alias"`
}

type PermSetter struct {
	conf Config

	db *sql.DB // the db connection to where the asanaSyncLog is located

	asanaClient *asana.Client

	googleClient *admin.Service

	MyOrgID string

	userIDtoEmail map[asana.UserID]string

	emailToUserID map[string]asana.UserID

	teams map[int64]bool // list of teams in the asana org (by teamID)

	teamIDtoName map[int64]string

	teamNameToID map[string]int64

	aliasesPerTeam map[int64]map[string]bool // for each team, which aliases should have permissions

	admins map[string]bool // list of admins that get onto each team

	projectIDtoName map[int64]string
}

func NewPermSetter(conf Config) (*PermSetter, error) {
	var db *sql.DB
	var err error

	if conf.MysqlConfig != nil {
		db, err = sql.Open("mysql", *conf.MysqlConfig)
		if err != nil {
			return nil, err
		}
	}

	ac, err := asana.NewClient(conf.AsanaPersonalAccessToken)
	if err != nil {
		return nil, err
	}

	if conf.GooglePemPath != nil {
		b, err := ioutil.ReadFile(*conf.GooglePemPath)
		if err != nil {
			return nil, err
		}
		conf.GooglePemValue = string(b)
	}

	gconf := &jwt.Config{
		Email:      conf.GooglePemEmail,
		PrivateKey: []byte(conf.GooglePemValue),
		Subject:    conf.GooglePemSubject,
		Scopes: []string{
			"https://www.googleapis.com/auth/admin.directory.group",
		},
		TokenURL: google.JWTTokenURL,
	}

	gc, err := admin.New(gconf.Client(oauth2.NoContext))
	if err != nil {
		return nil, err
	}

	return &PermSetter{
		conf:            conf,
		db:              db,
		asanaClient:     ac,
		googleClient:    gc,
		userIDtoEmail:   make(map[asana.UserID]string),
		emailToUserID:   make(map[string]asana.UserID),
		teams:           make(map[int64]bool),
		teamIDtoName:    make(map[int64]string),
		teamNameToID:    make(map[string]int64),
		aliasesPerTeam:  make(map[int64]map[string]bool),
		admins:          make(map[string]bool),
		projectIDtoName: make(map[int64]string),
	}, nil
}

func (ps *PermSetter) Close() {
	if ps.db != nil {
		ps.db.Close()
	}
}

var configPath = flag.String("config", "", "path to config file")

func main() {
	var conf Config
	flag.Parse()

	if *configPath == "" {
		if err := envconfig.Process("asanasync", &conf); err != nil {
			log.Fatalf("must specify the path to the config file (--config config-file) or env variables, err: %v", err)
		}
	} else {
		b, err := ioutil.ReadFile(*configPath)
		if err != nil {
			log.Fatalf("couldn't read in config file")
		}
		if err := yaml.Unmarshal(b, &conf); err != nil {
			log.Fatalf("unable to unmarshal config yaml file, err: %v", err)
		}
	}

	ps, err := NewPermSetter(conf)
	if err != nil {
		log.Fatal(err)
	}
	defer ps.Close()

	if err := ps.FetchOrganizationID(); err != nil {
		log.Fatal(err)
	}

	if err = ps.FetchUsers(); err != nil {
		log.Fatal(err)
	}

	if err = ps.FetchTeams(); err != nil {
		log.Fatal(err)
	}

	if err = ps.FetchAdmins(); err != nil {
		log.Fatal(err)
	}

	if err = ps.SetPermsForTeams(); err != nil {
		log.Fatal(err)
	}
}

func (ps *PermSetter) SetPermsForTeams() error {
	for tID, _ := range ps.teams {
		setTeam := func(teamID int64) error {
			belong := make(map[string]bool)
			for alias, _ := range ps.aliasesPerTeam[teamID] {
				if err := ps.GetGoogleGroupMembership(alias, belong); err != nil {
					if strings.Contains(err.Error(), "Resource Not Found: groupKey, notFound") {
						log.Printf("unable to find google group for %s\n", alias)
						continue
					}
					log.Fatal(err)
				}
			}
			for d, _ := range ps.admins {
				belong[d] = true
			}

			current := make(map[string]bool)
			if err := ps.FetchUsersForTeam(teamID, current); err != nil {
				log.Fatal(err)
			}

			for b, _ := range belong {
				if _, ok := current[b]; !ok {
					if err := ps.AddMemberToAsanaTeam(b, teamID); err != nil {
						if strings.Contains(err.Error(), "only_team_members_can_add_members") {
							return nil
						} else {
							return err
						}
					}
					current[b] = true
					if err := ps.LogTeamAddition(b, teamID); err != nil {
						log.Fatal(err)
					}
				}
			}

			for cur, _ := range current {
				if _, ok := belong[cur]; !ok {
					ans, err := ps.IsLoggedOnTeam(ps.emailToUserID[cur], teamID)
					if err != nil {
						log.Fatal(err)
					}
					if ans {
						if err := ps.RemoveFromTeamLog(cur, teamID); err != nil {
							log.Fatal(err)
						}
						if err := ps.RemoveMemberFromAsanaTeam(cur, teamID); err != nil {
							log.Fatal(err)
						}
						delete(current, cur)
					}
				}
			}

			projects := make(map[int64]*asana.Project)
			if err := ps.FetchProjectsForTeam(teamID, projects); err != nil {
				log.Fatal(err)
			}

			for _, project := range projects {
				fmt.Printf("checking project %s\n", project.Name)
				projBelong := make(map[string]bool)
				subs := strings.FieldsFunc(project.Notes, func(c rune) bool {
					return !unicode.IsLetter(c) && !unicode.IsNumber(c) && c != '@' && c != '_' && c != '.'
				})
				for _, sub := range subs {
					if !strings.HasSuffix(sub, strings.Join([]string{"@", ps.conf.WorkspaceName}, "")) {
						continue
					}
					if err := ps.GetGoogleGroupMembership(sub, projBelong); err != nil {
						if strings.Contains(err.Error(), "Resource Not Found: groupKey, notFound") {
							log.Printf("unable to find google group for %s in projectID %d\n", sub, project.ID)
							continue
						}
						log.Fatal(err)
					}
				}
				projCurrent := make(map[string]bool)
				for _, m := range project.Members {
					projCurrent[ps.userIDtoEmail[asana.UserID(m.ID)]] = true
				}
				for b, _ := range projBelong {
					if _, ok := projCurrent[b]; !ok {
						if _, ok := current[b]; !ok { // if already on team, no need to add to project
							log.Printf("add %s to projectID %d\n", b, project.ID)
							if err := ps.asanaClient.AddUsersToProject(&asana.ProjectRequest{
								ProjectGID: fmt.Sprintf("%d", project.ID),
								Members:    []string{b},
								Workspace:  ps.MyOrgID}); err != nil {
								if strings.Contains(err.Error(), "only_team_members_can_add_members") {
									return nil
								} else {
									log.Fatal(err)
								}
							}
							projCurrent[b] = true
							if err := ps.LogProjectAddition(b, project.ID); err != nil {
								log.Fatal(err)
							}
						}
					}
				}
				for cur, _ := range projCurrent {
					if _, ok := projBelong[cur]; !ok {
						ans, err := ps.IsLoggedOnProject(ps.emailToUserID[cur], project.ID)
						if err != nil {
							log.Fatal(err)
						}
						if ans {
							log.Printf("removing %s from projectID %d\n", cur, project.ID)
							if err := ps.RemoveFromProjectLog(cur, project.ID); err != nil {
								log.Fatal(err)
							}
							if err := ps.asanaClient.RemoveUsersFromProject(&asana.ProjectRequest{
								ProjectGID: fmt.Sprintf("%d", project.ID),
								Members:    []string{cur},
								Workspace:  ps.MyOrgID}); err != nil {
								log.Fatal(err)
							}
							delete(projCurrent, cur)
						}
					}
				}
			}
			return nil
		}
		if err := setTeam(tID); err != nil {
			return err
		}
	}
	return nil
}

func (ps *PermSetter) FetchOrganizationID() error {
	log.Printf("fetching organization info")
	workspacesChan, err := ps.asanaClient.ListMyWorkspaces()
	if err != nil {
		return err
	}

	for page := range workspacesChan {
		for _, workspace := range page.Workspaces {
			if workspace.Name == ps.conf.WorkspaceName {
				ps.MyOrgID = fmt.Sprintf("%v", workspace.ID)
			}
		}
	}
	return nil
}

func (ps *PermSetter) FetchUsers() error {
	log.Printf("fetching users for org")
	usersChan, _, err := ps.asanaClient.ListAllUsersInOrganization(ps.MyOrgID)
	if err != nil {
		return err
	}
	for page := range usersChan {
		if err := page.Err; err != nil {
			log.Printf("err :%v", err)
			continue
		}
		for _, u := range page.Users {
			ps.userIDtoEmail[u.UID] = u.Email
			ps.emailToUserID[u.Email] = u.UID
		}
	}
	return nil
}

func (ps *PermSetter) FetchTeams() error {
	log.Printf("fetching list of teams")
	pagesChan, _, err := ps.asanaClient.ListAllTeamsInOrganization(ps.MyOrgID)
	if err != nil {
		return err
	}

	for page := range pagesChan {
		if err := page.Err; err != nil {
			log.Printf("err: %v", err)
			continue
		}

		for _, team := range page.Teams {
			ps.teams[team.ID] = true
			ps.teamIDtoName[team.ID] = team.Name
			ps.teamNameToID[team.Name] = team.ID

			aliasStr := strings.Split(team.HtmlDescription, "\"")
			if len(aliasStr) > 1 {
				for _, sub := range aliasStr {
					if strings.HasPrefix(sub, "mailto:") && strings.HasSuffix(sub, strings.Join([]string{"@", ps.conf.WorkspaceName}, "")) {
						if _, ok := ps.aliasesPerTeam[team.ID]; !ok {
							ps.aliasesPerTeam[team.ID] = make(map[string]bool)
						}
						ps.aliasesPerTeam[team.ID][sub[7:]] = true
						log.Printf("adding alias %s to teamID %d", sub[7:], team.ID)
					}
				}
			}
		}
	}
	return nil
}

func (ps *PermSetter) FetchProjectsForTeam(teamID int64, projects map[int64]*asana.Project) error {
	pagesChan, _, err := ps.asanaClient.QueryForProjects(&asana.ProjectQuery{
		Archived:    false,
		WorkspaceID: ps.MyOrgID,
		TeamID:      fmt.Sprintf("%d", teamID),
	})

	if err != nil {
		return err
	}

	for page := range pagesChan {
		if err := page.Err; err != nil {
			log.Printf("couldn't read in page of projects, err: %v", err)
			continue
		}

		for _, project := range page.Projects {
			projects[project.ID] = project
			ps.projectIDtoName[project.ID] = project.Name
		}
	}

	return nil
}

func (ps *PermSetter) FetchUsersForTeam(teamID int64, users map[string]bool) error {
	log.Printf("fetching users for team: %s (ID: %d)", ps.teamIDtoName[teamID], teamID)
	usersPagesChan, _, err := ps.asanaClient.ListAllUsersInTeam(fmt.Sprintf("%v", teamID))
	if err != nil {
		return err
	}

	for page := range usersPagesChan {
		if err := page.Err; err != nil {
			log.Printf("err: %v", err)
			continue
		}

		for _, user := range page.Users {
			users[ps.userIDtoEmail[user.UID]] = true
		}
	}
	return nil
}

func (ps *PermSetter) RemoveFromTeamLog(uname string, teamID int64) error {
	log.Printf("deleting entry for %s in team %s from the asanaSyncLog", uname, ps.teamIDtoName[teamID])
	_, err := ps.db.Exec(`DELETE FROM asanaSyncLog WHERE user_id = ? and team_id = ?`, ps.emailToUserID[uname], teamID)
	return err
}

func (ps *PermSetter) LogTeamAddition(uname string, teamID int64) error {
	log.Printf("inserting entry for %s in team %s to the asanaSyncLog", uname, ps.teamIDtoName[teamID])
	_, err := ps.db.Exec(`INSERT IGNORE INTO asanaSyncLog (user_id, user_name, team_id, team_name) VALUES (?, ?, ?, ?)`, ps.emailToUserID[uname], uname, teamID, ps.teamIDtoName[teamID])
	return err
}

func (ps *PermSetter) IsLoggedOnTeam(uid asana.UserID, teamID int64) (bool, error) {
	var d int64
	err := ps.db.QueryRow(`SELECT user_id FROM asanaSyncLog WHERE asanaSyncLog.user_id = ? AND asanaSyncLog.team_id = ?`, uid, teamID).Scan(&d)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		} else {
			return false, err
		}
	}
	return true, nil
}

func (ps *PermSetter) RemoveFromProjectLog(uname string, projectID int64) error {
	log.Printf("deleting entry for %s from project %s from the asanaProjectSyncLog", uname, ps.projectIDtoName[projectID])
	_, err := ps.db.Exec(`DELETE FROM asanaProjectSyncLog WHERE user_id = ? and project_id = ?`, ps.emailToUserID[uname], projectID)
	return err
}

func (ps *PermSetter) LogProjectAddition(uname string, projectID int64) error {
	log.Printf("inserting entry for %s in project %s to the asanaProjectSyncLog", uname, ps.projectIDtoName[projectID])
	_, err := ps.db.Exec(`INSERT IGNORE INTO asanaProjectSyncLog (user_id, user_name, project_id, project_name) VALUES (?, ?, ?, ?)`, ps.emailToUserID[uname], uname, projectID, ps.projectIDtoName[projectID])
	return err
}

func (ps *PermSetter) IsLoggedOnProject(uid asana.UserID, projectID int64) (bool, error) {
	var d int64
	err := ps.db.QueryRow(`SELECT user_id FROM asanaProjectSyncLog WHERE asanaProjectSyncLog.user_id = ? AND asanaProjectSyncLog.project_id = ?`, uid, projectID).Scan(&d)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		} else {
			return false, err
		}
	}
	return true, nil
}

func (ps *PermSetter) RemoveMemberFromAsanaTeam(userName string, teamID int64) error {
	err := ps.asanaClient.RemoveUserFromTeam(&asana.TeamRequest{
		UserID: fmt.Sprintf("%d", ps.emailToUserID[userName]),
		TeamID: fmt.Sprintf("%d", teamID),
	})
	if err != nil {
		log.Printf("unable to remove %s (ID %d) from %s (ID %d), err: %v", userName, ps.emailToUserID[userName], ps.teamIDtoName[teamID], teamID, err)
	} else {
		log.Printf("removing %s (ID %d) from %s (ID %d)", userName, ps.emailToUserID[userName], ps.teamIDtoName[teamID], teamID)
	}
	return err
}

func (ps *PermSetter) AddMemberToAsanaTeam(userName string, teamID int64) error {
	_, err := ps.asanaClient.AddUserToTeam(&asana.TeamRequest{
		UserID: fmt.Sprintf("%d", ps.emailToUserID[userName]),
		TeamID: fmt.Sprintf("%d", teamID),
	})
	if err != nil {
		log.Printf("unable to add %s (ID %d) to %s (ID %d), err: %v", userName, ps.emailToUserID[userName], ps.teamIDtoName[teamID], teamID, err)
	} else {
		log.Printf("adding %s (ID %d) to %s (ID %d)", userName, ps.emailToUserID[userName], ps.teamIDtoName[teamID], teamID)
	}
	return err
}

func (ps *PermSetter) GetGoogleGroupMembership(alias string, users map[string]bool) error {
	members, err := ps.googleClient.Members.List(alias).IncludeDerivedMembership(true).MaxResults(3000).Do()
	if err != nil {
		return err
	}
	for _, m := range members.Members {
		if !strings.HasPrefix(m.Email, ps.conf.EmailPrefixFilter) {
			if _, ok := ps.emailToUserID[m.Email]; ok {
				users[m.Email] = true
			}
		}
	}
	return nil
}

func (ps *PermSetter) FetchAdmins() error {
	return ps.GetGoogleGroupMembership(ps.conf.AdminAlias, ps.admins)
}
