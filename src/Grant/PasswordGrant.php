<?php
/**
 * OAuth 2.0 Password grant.
 *
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Grant;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\UserEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;
use League\OAuth2\Server\RequestEvent;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ServerRequestInterface;

use App\Models\PassportMemory;

/**
 * Password grant class.
 */
class PasswordGrant extends AbstractGrant
{
    /**
     * @param UserRepositoryInterface         $userRepository
     * @param RefreshTokenRepositoryInterface $refreshTokenRepository
     */
    public function __construct(
        UserRepositoryInterface $userRepository,
        RefreshTokenRepositoryInterface $refreshTokenRepository
    ) {
        $this->setUserRepository($userRepository);
        $this->setRefreshTokenRepository($refreshTokenRepository);

        $this->refreshTokenTTL = new \DateInterval('P1M');
    }

    /**
     * {@inheritdoc}
     */
    public function respondToAccessTokenRequest(
        ServerRequestInterface $request,
        ResponseTypeInterface $responseType,
        \DateInterval $accessTokenTTL
    ) {
        // Validate request
        $client = $this->validateClient($request);
        $scopes = $this->validateScopes($this->getRequestParameter('scope', $request));
        $user = $this->validateUser($request, $client);

        // Finalize the requested scopes
        $scopes = $this->scopeRepository->finalizeScopes($scopes, $this->getIdentifier(), $client, $user->getIdentifier());

        // Issue and persist new tokens
        $accessToken = $this->issueAccessToken($accessTokenTTL, $client, $user->getIdentifier(), $scopes);
        $refreshToken = $this->issueRefreshToken($accessToken);

        // Inject tokens into response
        $responseType->setAccessToken($accessToken);
        $responseType->setRefreshToken($refreshToken);

        $userId = $accessToken->getUserIdentifier();

         // Converting unencrypted token to encrypted to pass to user model
        $user_access_token = $accessToken->convertToJWT($this->privateKey);
        $user_refresh_token = $this->encrypt(
            json_encode(
                [
                    'client_id'        => $accessToken->getClient()->getIdentifier(),
                    'refresh_token_id' => $refreshToken->getIdentifier(),
                    'access_token_id'  => $accessToken->getIdentifier(),
                    'scopes'           => $accessToken->getScopes(),
                    'user_id'          => $accessToken->getUserIdentifier(),
                    'expire_time'      => $refreshToken->getExpiryDateTime()->getTimestamp(),
                ]
            )
        );


        // get user data to set in memeory
        $user = $this->userRepository->getUserEntityDataByUserCredentials(
            $userId, $user_access_token, $user_refresh_token, $accessToken->getExpiryDateTime(), $refreshToken->getExpiryDateTime()
        )->getAttributes();

        if(isset($user['user_profile'])){
            $responseType->user_profile = $user['user_profile'];
        }

        // save user access and refresh tokens to redis
        if (PASSPORT_DRIVER == PASSPORT_MEMORY) {

            // access token data to set
            $accessTokenData    = array(
                'access_token'  => $accessToken->getIdentifier(),
                'client_id'     => $accessToken->getClient()->getIdentifier(),
                'user_id'       => $accessToken->getUserIdentifier(),
                'scopes'        => $accessToken->getScopes(),
                'revoked'       => 0,
                'expires_at'    => $accessToken->getExpiryDateTime(),
            );

            // refresh token data to set
            $refreshTokenData   = array(
                'refresh_token' => $refreshToken->getIdentifier(),
                'access_token'  => $refreshToken->getAccessToken()->getIdentifier(),
                'revoked'       => 0,
                'expires_at'    => $refreshToken->getExpiryDateTime(),
            );

            $userData = array();
            // get only required fields specified in constants
            foreach (PASSPORT_USER_DATA_TO_STORE as $colName) {
                $userData[$colName] = $user[$colName];
            }

            // set access toke data in memory
            PassportMemory::setGeneratedAccessTokenData($accessTokenData);

            // set refresh toke data in memory
            PassportMemory::setGeneratedRefreshTokenData($refreshTokenData);

            // set user data in memory
            PassportMemory::setUserData($userId, $userData);
        }

        return $responseType;
    }

    /**
     * @param ServerRequestInterface $request
     * @param ClientEntityInterface  $client
     *
     * @throws OAuthServerException
     *
     * @return UserEntityInterface
     */
    protected function validateUser(ServerRequestInterface $request, ClientEntityInterface $client)
    {
        $username = $this->getRequestParameter('username', $request);
        if (is_null($username)) {
            throw OAuthServerException::invalidRequest('username');
        }

        $password = $this->getRequestParameter('password', $request);
        if (is_null($password)) {
            throw OAuthServerException::invalidRequest('password');
        }

        $user = $this->userRepository->getUserEntityByUserCredentials(
            $username,
            $password,
            $this->getIdentifier(),
            $client
        );
        if ($user instanceof UserEntityInterface === false) {
            $this->getEmitter()->emit(new RequestEvent(RequestEvent::USER_AUTHENTICATION_FAILED, $request));

            throw OAuthServerException::invalidCredentials();
        }

        return $user;
    }

    /**
     * {@inheritdoc}
     */
    public function getIdentifier()
    {
        return 'password';
    }
}
