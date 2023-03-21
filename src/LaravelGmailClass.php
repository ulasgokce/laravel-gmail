<?php

namespace Dacastro4\LaravelGmail;

use App\GmailSenderIntegration;
use Dacastro4\LaravelGmail\Exceptions\AuthException;
use Dacastro4\LaravelGmail\Services\Message;
use Illuminate\Support\Facades\Redirect;

class LaravelGmailClass extends GmailConnection
{
    public function __construct($config, $userId = null)
    {
        if (class_basename($config) === 'Application') {
            $config = $config['config'];
        }

        parent::__construct($config, $userId);
    }

    /**
     * @return Message
     * @throws AuthException
     */
    public function message($user_id,$email)
    {
        $token=$this->getToken($user_id,$email);
        if (!isset($token)) {
            throw new AuthException('No credentials found.');
        }

        return new Message($this);
    }

    /**
     * Returns the Gmail user email
     *
     * @return \Google_Service_Gmail_Profile
     */
    public function user()
    {
        return $this->config(null, null, 'email');
    }

    /**
     * Updates / sets the current userId for the service
     *
     * @return \Google_Service_Gmail_Profile
     */
    public function setUserId($userId)
    {
        $this->userId = $userId;
        return $this;
    }

    public function redirect($state)
    {
        return Redirect::to($this->getAuthUrl($state));
    }

    /**
     * Gets the URL to authorize the user
     *
     * @return string
     */
    public function getAuthUrl($state)
    {
        return $this->createAuthUrl($state);
    }

    public function logout($user_id, $email)
    {
        $integration = GmailSenderIntegration::where('user_id', $user_id)->where('email', $email)->first();

        $this->revokeToken(json_decode($integration->config,true));
        $integration->delete();
    }

}
