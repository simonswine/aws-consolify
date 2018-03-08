package awsconsolify

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"

	"github.com/Sirupsen/logrus"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	vault "github.com/hashicorp/vault/api"
	"github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
)

const FlagExportVars = "export-vars"
const FlagRegion = "region"
const FlagSeperateProfile = "seperate-profile"

const DefaultRegion = "us-east-1"

const FederationURL = "https://signin.aws.amazon.com/federation"
const ConsoleURL = "https://console.aws.amazon.com"

const PolicyAllowAll = `{
  "Version":"2012-10-17",
  "Statement":[
    {
      "Sid":"AllowAll",
      "Effect":"Allow",
      "Action":["*"],
      "Resource":["*"]
    }
  ]
}`

type vaultLogical interface {
	Read(path string) (*vault.Secret, error)
}

type VaultAWS struct {
	log     *logrus.Logger
	session *session.Session
	region  string
	args    []string
}

func New() *VaultAWS {
	logger := logrus.New()
	logger.Out = os.Stderr
	logger.Level = logrus.DebugLevel
	return &VaultAWS{
		log:    logger,
		region: DefaultRegion,
	}
}

// this method gets a cached session or creates new ones from vault or aws cfg
func (v *VaultAWS) Session() (*session.Session, error) {
	return v.newSessionCfg()
}

func (v *VaultAWS) SessionSTS() (*session.Session, error) {
	sess, err := v.Session()
	if err != nil {
		return nil, err
	}

	creds, err := sess.Config.Credentials.Get()
	if err != nil {
		return nil, fmt.Errorf("error getting credentials: %s", err)
	}

	if creds.SessionToken == "" {
		v.log.Debug("getting new session token")
		svc := sts.New(sess)

		sessionToken, err := svc.GetFederationToken(&sts.GetFederationTokenInput{
			Name:   aws.String("aws-consolify"),
			Policy: aws.String(PolicyAllowAll),
		})
		if err != nil {
			return nil, fmt.Errorf("error getting federation token: %s", err)
		}

		v.log.Debugf("got new session token access_key=%s, expiration=%s", *sessionToken.Credentials.AccessKeyId, sessionToken.Credentials.Expiration.String())

		creds := credentials.NewStaticCredentials(*sessionToken.Credentials.AccessKeyId, *sessionToken.Credentials.SecretAccessKey, *sessionToken.Credentials.SessionToken)

		return session.NewSession(&aws.Config{
			Region:      &v.region,
			Credentials: creds,
		})
	}

	return sess, nil
}

func (v *VaultAWS) ConsoleURL() string {
	consoleURL, err := url.Parse(ConsoleURL)
	if err != nil {
		panic(err)
	}
	consoleURL.Host = fmt.Sprintf("%s.%s", v.region, consoleURL.Host)
	return consoleURL.String()
}

func (v *VaultAWS) SigninURL() (string, error) {
	sess, err := v.SessionSTS()
	if err != nil {
		return "", fmt.Errorf("error getting session: %s", err)
	}

	creds, err := sess.Config.Credentials.Get()
	if err != nil {
		return "", fmt.Errorf("error getting credentials: %s", err)
	}

	sessionObj := struct {
		SessionID    string `json:"sessionId"`
		SessionKey   string `json:"sessionKey"`
		SessionToken string `json:"sessionToken"`
	}{
		SessionID:    creds.AccessKeyID,
		SessionKey:   creds.SecretAccessKey,
		SessionToken: creds.SessionToken,
	}

	sessionJSON, err := json.Marshal(sessionObj)
	if err != nil {
		return "", err
	}
	v.log.Debugf("requesting federation login URL body='%s'", string(sessionJSON))

	federationParams := url.Values{}
	federationParams.Add("Action", "getSigninToken")
	federationParams.Add("Session", string(sessionJSON))
	federationURL := fmt.Sprintf("%s?%s", FederationURL, federationParams.Encode())

	federationResponse, err := http.Get(federationURL)
	if err != nil {
		return "", fmt.Errorf("fetching federated signin Token: %s", err)
	}
	if federationResponse.StatusCode != 200 {
		return "", fmt.Errorf("unexpected return code fetching federated signin Token: %d", federationResponse.StatusCode)
	}

	defer federationResponse.Body.Close()
	tokenJSON, err := ioutil.ReadAll(federationResponse.Body)
	if err != nil {
		return "", err
	}

	tokenObj := struct {
		SigninToken string `json:"SigninToken"`
	}{}

	if err := json.Unmarshal(tokenJSON, &tokenObj); err != nil {
		return "", fmt.Errorf("unable to decode JSON with signin token: %s", err)
	}

	signinParams := url.Values{}
	signinParams.Add("Action", "login")
	signinParams.Add("Destination", v.ConsoleURL())
	signinParams.Add("SigninToken", tokenObj.SigninToken)

	return fmt.Sprintf("%s\n", fmt.Sprintf("%s?%s", FederationURL, signinParams.Encode())), nil
}

func (v *VaultAWS) newSessionVault() (*session.Session, error) {
	return nil, errors.New("implement me")
}

func (v *VaultAWS) newSessionCfg() (*session.Session, error) {
	return session.NewSessionWithOptions(
		session.Options{
			SharedConfigState: session.SharedConfigEnable,
			Config: aws.Config{
				Region: &v.region,
			},
		},
	)
}

func (v *VaultAWS) Must(err error) {
	if err != nil {
		v.log.Fatal(err)
	}
}

func (v *VaultAWS) parseRegion(cmd *cobra.Command) error {
	region, err := cmd.Flags().GetString(FlagRegion)
	if err != nil {
		return err
	}

	// TODO: validate region name
	v.region = region
	return nil
}

// return a hash for every account, allows running multiple console sessions
func (v *VaultAWS) profileHash() (string, error) {
	sess, err := v.Session()
	if err != nil {
		return "", err
	}

	creds, err := sess.Config.Credentials.Get()

	if err != nil {
		return "", err
	}

	return creds.ProviderName, nil
}

func (v *VaultAWS) CmdConsoleURL(cmd *cobra.Command, args []string) error {
	v.args = args
	if err := v.parseRegion(cmd); err != nil {
		return err
	}

	url, err := v.SigninURL()
	if err != nil {
		return err
	}

	fmt.Println(url)
	return nil
}

func (v *VaultAWS) CmdConsole(cmd *cobra.Command, args []string) error {
	v.args = args
	if err := v.parseRegion(cmd); err != nil {
		return err
	}

	url, err := v.SigninURL()
	if err != nil {
		return err
	}

	executable := "xdg-open"
	if runtime.GOOS == "darwin" {
		executable = "open"
	}

	c := exec.Command(executable, url)
	return c.Start()

}

func (v *VaultAWS) CmdConsoleChrome(cmd *cobra.Command, args []string) error {
	v.args = args
	if err := v.parseRegion(cmd); err != nil {
		return err
	}

	url, err := v.SigninURL()
	if err != nil {
		return err
	}

	executable := "google-chrome"
	if runtime.GOOS == "darwin" {
		executable = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
	}

	var chromeArgs []string

	if false {
		profileHash, err := v.profileHash()
		if err != nil {
			return err
		}

		profilePath, err := homedir.Expand(fmt.Sprintf("~/.chrome-%s", profileHash))
		if err != nil {
			return err
		}
		chromeArgs = append(chromeArgs, []string{
			fmt.Sprintf("--user-data-dir=%s", profilePath),
			"--no-first-run",
		}...)
	}

	chromeArgs = append(chromeArgs, url)

	c := exec.Command(executable, chromeArgs...)
	return c.Start()

}

func (v *VaultAWS) CmdConsoleFirefox(cmd *cobra.Command, args []string) error {
	return errors.New("not implemented :(")
}

func (v *VaultAWS) CmdEnv(cmd *cobra.Command, args []string) error {
	v.args = args
	sess, err := v.SessionSTS()
	if err != nil {
		return fmt.Errorf("error getting session: %s", err)
	}

	creds, err := sess.Config.Credentials.Get()
	if err != nil {
		return fmt.Errorf("error getting credentials: %s", err)
	}

	prefix := "export "
	if export, err := cmd.Flags().GetBool(FlagExportVars); err == nil && !export {
		prefix = ""
	}

	fmt.Printf("%sAWS_ACCESS_KEY_ID=%s\n", prefix, creds.AccessKeyID)
	fmt.Printf("%sAWS_SECRET_ACCESS_KEY=%s\n", prefix, creds.SecretAccessKey)
	if creds.SessionToken != "" {
		fmt.Printf("%sAWS_SESSION_TOKEN=%s\n", prefix, creds.SessionToken)
	}

	return nil
}
