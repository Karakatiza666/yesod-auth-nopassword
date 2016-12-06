-- | An auth plugin for email-based passwordless registration.
--
-- Basic flow:
--
-- * Enter email address
-- * If user does not exist, create in the database and add a login token.
-- * If the user does exist, write a login token to the database.
-- * Email the login token to the user.
-- * User opens the website from the login token and is authenticated.
--
-- Configuration:
--
-- * Post email handler (i.e. "We've sent you an email")
-- * Post login handler (i.e. returning from link in email)
--
-- This plugin provides no "UI", it is up to the developer to create forms for
-- use in this login flow, and to POST those at the handlers provided here.
-- An EmailForm data type is provided, and this must be what the forms unwrap to.
--
-- If the form is successful, the user will be redirected to the route
-- specified in the NoPasswordAuth instance, otherwise they will be returned
-- back to the login route with an error message.

module Yesod.Auth.NoPassword (
    -- Plugin
      authNoPassword
    -- Form Type
    , EmailForm(..)
    -- Typeclass
    , NoPasswordAuth(..)
    -- Utility
    , loginPostR
) where

import Prelude

import Data.Monoid ((<>))
import Data.Text
import Data.Text.Encoding (encodeUtf8, decodeUtf8)
import qualified Text.Blaze as B

import qualified Data.UUID as U
import qualified Data.UUID.V4 as U

import Network.HTTP.Types.URI (urlEncode, urlDecode)

import Yesod.Core
import Yesod.Form
import Yesod.Auth
import Crypto.PasswordStore

-- Constants

pluginName :: Text
pluginName = "email"

-- | Route to POST the login form at
loginPostR :: AuthRoute
loginPostR = PluginR pluginName ["login"]


tokenStrength :: Int
tokenStrength = 17 -- 2^tokenStrength hash rounds

tokenParamName :: Text
tokenParamName = "tkn"

type Email = Text
type Token = Text
type TokenId = Text
type Hash = Text

-- | Data type required for the form
data EmailForm = EmailForm
    { efEmail :: Email
    }

-- Convenience alias for forms
type Form m a = (Html -> MForm (HandlerT m IO) (FormResult a, WidgetT m IO ()))


-- | Yesod.Auth plugin defintion
authNoPassword :: NoPasswordAuth m
               => Form m EmailForm
               -> AuthPlugin m
authNoPassword form = AuthPlugin pluginName dispatch login
    where
        login _ = error "NoPasswordAuth does not provide a login widget"

        dispatch "POST" ["login"] = postEmailR form
        dispatch "GET"  ["login"] = getLoginR
        dispatch _ _ = notFound


postEmailR :: NoPasswordAuth m
           => Form m EmailForm
           -> HandlerT Auth (HandlerT m IO) TypedContent
postEmailR form = do
    ((result, _), _) <- lift $ runFormPost form
    master <- lift getYesod
    case result of
        FormMissing -> do
            setMessage "Something went wrong, please try again"
            lift $ redirect (emailSentRoute master)
        FormFailure as -> do
            mapM_ (setMessage . B.text) as
            lift $ redirect (emailSentRoute master)
        FormSuccess e -> do
            let email = efEmail e
            (hash, token) <- liftIO $ genToken
            muser <- lift $ getUserByEmail (efEmail e)
            tid <- liftIO genTokenId
            case muser of
                Just user ->
                    lift $ updateLoginHashForUser user (Just hash) tid
                Nothing ->
                    lift $ newUserWithLoginHash email hash tid
            setMessage $ B.text "Check your email for a login link"
            url <- genUrl token tid
            lift $ sendLoginEmail email url
            lift $ redirect (emailSentRoute master)


getLoginR :: NoPasswordAuth m => HandlerT Auth (HandlerT m IO) TypedContent
getLoginR = do
    loginParam <- lookupGetParam tokenParamName
    case (unpackTokenParam loginParam) of
        Nothing -> permissionDenied "Missing login token"
        Just (tid, loginToken) -> do
            muser <- lift $ getEmailAndHashByTokenId tid
            case muser of
                Nothing -> permissionDenied "No login token sent"
                Just (email, hash) ->
                    if (verifyToken hash loginToken)
                        then lift $ setCredsRedirect (Creds pluginName email [])
                        else permissionDenied "Incorrect login token"


unpackTokenParam :: Maybe Text -> Maybe (TokenId, Token)
unpackTokenParam param =
    case param of
        Nothing -> Nothing
        Just p -> case (splitOn ":" p) of
            (tid:tkn:[]) -> Just (tid, tkn)
            _ -> Nothing


genToken :: IO (Hash, Token)
genToken = do
    tokenSalt <- genSaltIO
    let token = exportSalt tokenSalt
    hash <- makePassword token tokenStrength
    return (decodeUtf8 hash, decodeUtf8 (urlEncode False token))


verifyToken :: Hash -> Token -> Bool
verifyToken hash token = verifyPassword t h
    where
        h = encodeUtf8 hash
        t = urlDecode False (encodeUtf8 token)


genTokenId :: IO TokenId
genTokenId = do
    uuid <- U.nextRandom
    return $ U.toText uuid


genUrl :: Token -> TokenId -> HandlerT Auth (HandlerT m IO) Text
genUrl token tid = do
    tm <- getRouteToParent
    render <- lift getUrlRender
    return $ (render $ tm loginPostR) <> genQuery
    where
        genParam = tid <> ":" <> token
        genQuery = "?" <> tokenParamName <> "=" <> genParam


class YesodAuthPersist master => NoPasswordAuth master where
    -- | Route to a page that dispays a login form. This is not provided by
    -- the plugin.
    loginRoute :: master -> Route master

    -- | Route to be sent after entering an email address. This is not
    -- provided by the plugin. Note that the user will not be authenticated
    -- when they reach the page.
    emailSentRoute :: master -> Route master

    -- | Send login email
    sendLoginEmail :: Email -> Text -> HandlerT master IO ()

    -- | Get a user by their email address
    getUserByEmail :: Email -> HandlerT master IO (Maybe (AuthId master))

    -- | Get a Hash by its TokenId
    getEmailAndHashByTokenId :: TokenId -> HandlerT master IO (Maybe (Email, Hash))

    -- | Update a user's login hash
    -- This is also used to blank out the hash once the user has logged in, or to
    -- prevent the user from logging in, so must accept a value of `Nothing`.
    updateLoginHashForUser :: (AuthId master) -> Maybe Hash -> TokenId -> HandlerT master IO ()

    -- | Create a new user with an email address and hash
    newUserWithLoginHash :: Email -> Hash -> TokenId -> HandlerT master IO ()

    {-
        MINIMAL loginRoute
              , emailSentRoute
              , sendLoginEmail
              , getUserByEmail
              , getEmailAndHashByTokenId
              , updateLoginHashForUser
              , newUserWithLoginHash
    -}
