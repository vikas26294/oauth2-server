<?php
/**
 * OAuth 2.0 Refresh token grant.
 *
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Grant;

use DateInterval;
use Exception;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\RequestEvent;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ServerRequestInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;

use App\Models\PassportMemory;

/**
 * Refresh token grant.
 */
class RefreshTokenGrant extends AbstractGrant
{
    /**
     * @param RefreshTokenRepositoryInterface $refreshTokenRepository
     */
    public function __construct(RefreshTokenRepositoryInterface $refreshTokenRepository, UserRepositoryInterface $userRepository)
    {
        $this->setRefreshTokenRepository($refreshTokenRepository);
        $this->setUserRepository($userRepository);

        $this->refreshTokenTTL = new DateInterval('P1M');
    }

    /**
     * {@inheritdoc}
     */
    public function respondToAccessTokenRequest(
        ServerRequestInterface $request,
        ResponseTypeInterface $responseType,
        DateInterval $accessTokenTTL
    ) {
        // Validate request
        $client = $this->validateClient($request);
        $oldRefreshToken = $this->validateOldRefreshToken($request, $client->getIdentifier());
        $scopes = $this->validateScopes($this->getRequestParameter(
            'scope',
            $request,
            implode(self::SCOPE_DELIMITER_STRING, $oldRefreshToken['scopes']))
        );

        // The OAuth spec says that a refreshed access token can have the original scopes or fewer so ensure
        // the request doesn't include any new scopes
        foreach ($scopes as $scope) {
            if (in_array($scope->getIdentifier(), $oldRefreshToken['scopes'], true) === false) {
                throw OAuthServerException::invalidScope($scope->getIdentifier());
            }
        }

        // Expire old tokens
        $this->accessTokenRepository->revokeAccessToken($oldRefreshToken['access_token_id']);
        $this->refreshTokenRepository->revokeRefreshToken($oldRefreshToken['refresh_token_id']);

        // Issue and persist new access token
        $accessToken = $this->issueAccessToken($accessTokenTTL, $client, $oldRefreshToken['user_id'], $scopes);
        $this->getEmitter()->emit(new RequestEvent(RequestEvent::ACCESS_TOKEN_ISSUED, $request));
        $responseType->setAccessToken($accessToken);

        // Issue and persist new refresh token if given
        $refreshToken = $this->issueRefreshToken($accessToken);

        if ($refreshToken !== null) {
            $this->getEmitter()->emit(new RequestEvent(RequestEvent::REFRESH_TOKEN_ISSUED, $request));
            $responseType->setRefreshToken($refreshToken);
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

            // set access toke data in memory
            PassportMemory::setGeneratedAccessTokenData($accessTokenData);

            // set refresh toke data in memory
            PassportMemory::setGeneratedRefreshTokenData($refreshTokenData);
        }

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
        
        $userId = $accessToken->getUserIdentifier();

        // get user data to response
        $user = $this->userRepository->getUserEntityDataByUserCredentials(
            $userId, $user_access_token, $user_refresh_token, $accessToken->getExpiryDateTime(), $refreshToken->getExpiryDateTime()
        )->getAttributes();

        if(isset($user['user_profile'])){
            $responseType->user_profile = $user['user_profile'];
        }

        return $responseType;
    }

    /**
     * @param ServerRequestInterface $request
     * @param string                 $clientId
     *
     * @throws OAuthServerException
     *
     * @return array
     */
    protected function validateOldRefreshToken(ServerRequestInterface $request, $clientId)
    {
        $encryptedRefreshToken = $this->getRequestParameter('refresh_token', $request);
        if (is_null($encryptedRefreshToken)) {
            throw OAuthServerException::invalidRequest('refresh_token');
        }

        // Validate refresh token
        try {
            $refreshToken = $this->decrypt($encryptedRefreshToken);
        } catch (Exception $e) {
            throw OAuthServerException::invalidRefreshToken('Cannot decrypt the refresh token', $e);
        }

        $refreshTokenData = json_decode($refreshToken, true);
        if ($refreshTokenData['client_id'] !== $clientId) {
            $this->getEmitter()->emit(new RequestEvent(RequestEvent::REFRESH_TOKEN_CLIENT_FAILED, $request));
            throw OAuthServerException::invalidRefreshToken('Token is not linked to client');
        }

        if ($refreshTokenData['expire_time'] < time()) {
            throw OAuthServerException::invalidRefreshToken('Token has expired');
        }

        if ($this->refreshTokenRepository->isRefreshTokenRevoked($refreshTokenData['refresh_token_id']) === true) {
            throw OAuthServerException::invalidRefreshToken('Token has been revoked');
        }

        return $refreshTokenData;
    }

    /**
     * {@inheritdoc}
     */
    public function getIdentifier()
    {
        return 'refresh_token';
    }
}
