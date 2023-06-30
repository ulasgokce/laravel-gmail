<?php

namespace Dacastro4\LaravelGmail;

use App\GmailSenderIntegration;
use Dacastro4\LaravelGmail\Traits\Configurable;
use Dacastro4\LaravelGmail\Traits\HasLabels;
use Google_Client;
use Google_Service_Gmail;
use Google_Service_Gmail_WatchRequest;
use Illuminate\Container\Container;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Request;
use Illuminate\Support\Facades\Storage;


class GmailConnection extends Google_Client
{
    use HasLabels;
    use Configurable {
        __construct as configConstruct;
    }


    protected $emailAddress;
    protected $refreshToken;
    protected $app;
    protected $accessToken;
    protected $token;
    private $configuration;
    public $userId;

    public function __construct($config = null, $userId = null)
    {
        $this->app = Container::getInstance();

        $this->userId = $userId;

        $this->configConstruct($config);

        $this->configuration = $config;

        parent::__construct($this->getConfigs());

        $this->configApi();
    }

    /**
     * Check and return true if the user has previously logged in without checking if the token needs to refresh
     *
     * @return bool
     */
    public function checkPreviouslyLoggedIn($user_id, $email)
    {
        $integration = GmailSenderIntegration::where('user_id', $user_id)->where('email', $email)->first();

        if (isset($integration)) {
            $savedConfigToken = json_decode($integration->config, true);
            return !empty($savedConfigToken['access_token']);
        }

    }

    /**
     * Refresh the auth token if needed
     *
     * @return mixed|null
     */
    private function refreshTokenIfNeeded($user_id, $email)
    {
        $integration = GmailSenderIntegration::where('user_id', $user_id)->where('email', $email)->first();
        $token = json_decode($integration->config, true);
        if ($this->isAccessTokenExpired($user_id, $email)) {
            if ($token['refresh_token']) {
                $response = $this->fetchAccessTokenWithRefreshToken($token['refresh_token']);
                $integration->config = json_encode($response);
                $integration->save();
                $token = $response;
                $this->setAccessToken($token);
            }
            return $token;
        }

        return $this->token;
    }

    /**
     * Check if token exists and is expired
     * Throws an AuthException when the auth file its empty or with the wrong token
     *
     *
     * @return bool Returns True if the access_token is expired.
     */
    public function isAccessTokenExpired($user_id, $email)
    {
        $token = $this->getToken($user_id, $email);
        try {
            if ($token) {
                $this->setAccessToken($token);
            }
        } catch (Exception $e) {
            Log::info(json_encode($token));
            Log::info('Token is invalid');
        }
    

        return parent::isAccessTokenExpired($user_id, $email);
    }

    public function getToken($user_id = null, $email = null)
    {
        return $this->config($user_id, $email);
    }

    public function setToken($token)
    {

        $this->setAccessToken($token);
    }

    public function getAccessToken()
    {
        $token = parent::getAccessToken() ?: $this->config();

        return $token;
    }

    /**
     * @param array|string $token
     */
    public function setAccessToken($token)
    {
        parent::setAccessToken($token);
    }

    /**
     * @param $token
     */
    public function setBothAccessToken($token, $user_id)
    {
        $this->setAccessToken($token);
        return $this->saveAccessToken($token, $user_id);
    }

    /**
     * Save the credentials in a file
     *
     * @param array $config
     */
    public function saveAccessToken(array $config, $user_id)
    {
        $config['email'] = $this->emailAddress;

        if (!GmailSenderIntegration::where('email', $this->emailAddress)->where('user_id', $user_id)->exists()) {
            return GmailSenderIntegration::create([
                'user_id' => $user_id,
                'email' => $this->emailAddress,
                'config' => json_encode($config),
            ]);

        }
        return null;
    }


    /**
     * @return array|string
     * @throws \Exception
     */
    public function makeToken($state)
    {
        $user_id = $state;
        $request = Request::capture();
        $code = (string) $request->input('code', null);
        if (!is_null($code) && !empty($code)) {
            $accessToken = $this->fetchAccessTokenWithAuthCode($code);
            if ($this->haveReadScope()) {
                $me = $this->getProfile();
                if (property_exists($me, 'emailAddress')) {
                    $this->emailAddress = $me->emailAddress;
                    $accessToken['email'] = $me->emailAddress;
                }
            }

            return $this->setBothAccessToken($accessToken, $user_id);

        } else {
            throw new \Exception('No access token');
        }
    }

    /**
     * Check
     *
     * @return bool
     */
    public function check($user_id, $email)
    {
        $integration = GmailSenderIntegration::where('user_id', $user_id)->where('email', $email)->first();

        if (isset($integration)) {
            $this->refreshTokenIfNeeded($user_id, $email);
            return true;
        }
        return false;
    }

    /**
     * Gets user profile from Gmail
     *
     * @return \Google_Service_Gmail_Profile
     */
    public function getProfile()
    {
        $service = new Google_Service_Gmail($this);

        return $service->users->getProfile('me');
    }

    /**
     * Revokes user's permission and logs them out
     */
    public function logout($user_id, $email)
    {
        $integration = GmailSenderIntegration::where('user_id', $user_id)->where('email', $email)->first();

        $this->revokeToken(json_decode($integration->config, true));
    }

    /**
     * Delete the credentials in a file
     */
    public function deleteAccessToken($user_id, $email)
    {
        GmailSenderIntegration::where('user_id', $user_id)->where('email', $email)->delete();

    }

    private function haveReadScope()
    {
        $scopes = $this->getUserScopes();

        return in_array(Google_Service_Gmail::GMAIL_READONLY, $scopes);
    }

    /**
     * users.stop receiving push notifications for the given user mailbox.
     *
     * @param string $userEmail Email address
     * @param array $optParams
     * @return \Google_Service_Gmail_Stop
     */
    public function stopWatch($userEmail, $optParams = [])
    {
        $service = new Google_Service_Gmail($this);

        return $service->users->stop($userEmail, $optParams);
    }

    /**
     * Set up or update a push notification watch on the given user mailbox.
     *
     * @param string $userEmail Email address
     * @param Google_Service_Gmail_WatchRequest $postData
     *
     * @return \Google_Service_Gmail_WatchResponse
     */
    public function setWatch($userEmail, \Google_Service_Gmail_WatchRequest $postData): \Google_Service_Gmail_WatchResponse
    {
        $service = new Google_Service_Gmail($this);

        return $service->users->watch($userEmail, $postData);
    }

    /**
     * Lists the history of all changes to the given mailbox. History results are returned in chronological order (increasing historyId).
     * @param $userEmail
     * @param $params
     * @return \Google\Service\Gmail\ListHistoryResponse
     */
    public function historyList($userEmail, $params)
    {
        $service = new Google_Service_Gmail($this);

        return $service->users_history->listUsersHistory($userEmail, $params);
    }
}