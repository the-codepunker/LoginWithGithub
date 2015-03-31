<?php

namespace Codepunker\LoginWithGithub;

/**
 * @package Codepunker\LoginWithGithub
 * @description Authenticates users against the GitHub API & the Slim FrameWork.
 */
class LoginWithGithub
{
    /**
     * A list of scopes to be requested from Github or an empty string to request only the public info
     * @var string
     */
    public $scopes          = '';

    /**
     * The code that was received from github upon user confirmation of access rights (used to get the token)
     * @var string
     */
    private $code_received  = null;

    /**
     * The random code generated here and received back from github after the user authorizes access rights
     * The two codes should match.
     * @var string
     */
    private $rand_received  = null;

    /**
     * @var string
     */
    private $access_token   = null;

    /**
     * The Slim framework instance passed as an argument in the constructor
     * @var object
     */
    private $slim           = null;

    /**
     * An array containing the Github Api configuration elements
     * @var array
     */
    private $config         = null;

    /**
     * loads the config and stores get variables needed for various verifications
     * @return void
     */
    public function __construct(\Slim\Slim $app)
    {
        $this->slim = $app;
        $this->config = $this->slim->config('Codepunker\LoginWithGithub');

        $this->code_received = $this->slim->request->get('code');
        $this->rand_received = $this->slim->request->get('state');
    }

    /**
     * Stores a random string in the session if not already set
     * @return string [the random string to be sent as "state" to GitHub]
     */
    private function generateRand()
    {
        if (!empty($_SESSION['rand_set'])) {
            return $_SESSION['rand_set'];
        }

        $salt = openssl_random_pseudo_bytes(10);
        $salt = hash("sha256", $salt);
        $_SESSION["rand_set"] = $salt;
        return $salt;
    }

    /**
     * @return string [link that takes users to Github]
     */
    public function generateLink()
    {
        $out =  'https://github.com/login/oauth/authorize/?' .
                'client_id=' . $this->config['client_id'] .
                '&state=' . $this->generateRand() .
                '&scope=' . $this->scopes;

        return $out;
    }

    /**
     * Goes through the entire process of obtaining the user information
     * 1. Checks if the user returned on the website with the "rand_set" generated in generateRand
     * 2. Checks whether Github retuned a proper code to be used when requesting a token
     * 3. Requests a token
     * 4. Requests user info based on the token
     * @return object [the github user object]
     */
    public function processAuthorization()
    {

        $error = true;
        if (empty($_SESSION["rand_set"]) or $_SESSION["rand_set"]!==$this->rand_received) {
            throw new \Exception("The received random string doesn't match what was initially sent");
        }

        if (empty($this->code_received)) {
            throw new \Exception("Invalid code received");
        }

        unset($_SESSION["rand_set"]); //for future requests generate a new random

        $resp = $this->requestToken();
        $this->access_token = $resp->access_token;

        $info = $this->requestPublicInfo();
        return $info;
    }

    /**
     * @return object [Response from Github containing the access token]
     */
    private function requestToken()
    {
        $url = 'https://github.com/login/oauth/access_token';
        $fields = [
                    'client_id' => $this->config['client_id'],
                    'client_secret' => $this->config['client_secret'],
                    'code' => $this->code_received
                    ];

        $options = [
                    CURLOPT_RETURNTRANSFER => 1,
                    CURLOPT_URL => $url,
                    CURLOPT_POST => 1,
                    CURLOPT_POSTFIELDS => http_build_query($fields),
                    CURLOPT_HTTPHEADER => ["Accept: application/json", "user-agent: " . $this->config['app_name']],
                    ];
        $resp = $this->sendRequest($url, $options);

        if (isset($resp->error)) {
            throw new \Exception("GitHub error: " . $resp->error_description);
        }

        if (empty($resp->access_token)) {
            throw new \Exception("GitHub error: Authorization token missing");
        }

        return $resp;
    }

    /**
     * @return object [Response from Github containing the user info]
     */
    private function requestPublicInfo()
    {
        $url = 'https://api.github.com/user?access_token=' . $this->access_token;
        $options = [
                    CURLOPT_RETURNTRANSFER => 1,
                    CURLOPT_URL => $url,
                    CURLOPT_HTTPHEADER => array("Accept: application/json", "user-agent: " . $this->config['app_name']),
                    ];
        $resp = $this->sendRequest($url, $options);

        if (isset($resp->error)) {
            throw new \Exception("GitHub error: " . $resp->error_description);
        }

        return $resp;
    }

    /**
     * A helper method to send out the various requests
     * @param  string $url
     * @param  array  $options CURL request options
     * @return object          [Whatever response Github sent back]
     */
    private function sendRequest($url, array $options)
    {
        $curl = curl_init();
        curl_setopt_array($curl, $options);

        $resp = curl_exec($curl);
        $code = curl_getinfo($curl, CURLINFO_HTTP_CODE);

        if ($code!='200') {
            throw new \Exception("Something went wrong when trying to contact GitHub. Please try again later.");
        }

        if (empty($resp)) {
            throw new \Exception("Something went wrong when trying to contact GitHub. Please try again later.");
        }

        $resp = json_decode($resp);
        if (empty($resp)) {
            throw new \Exception("I wasn't able to process the response");
        }

        return $resp;
    }
}
