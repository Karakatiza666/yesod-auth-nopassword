-- | This auth plugin for Yesod enabled simple passwordless authentication.
--
-- The only detail required from a user is an email address, and accounts are
-- either updated or created, depending on whether the account exists or not.
-- To actually log in, users are sent an email containing a link that
-- authenticates them and logs them in.
--
-- This plugin provides:
--
-- * Token generation
-- * Orchestration of the login process and email sending
-- * Receiving of the login form data via HTTP POST.
-- * Authentication of users once they return to the site from an email
--
-- This plugin /does not/ provide:
--
-- * A login form
-- * Email rendering or sending
-- * An account model
-- * A viewable interface (i.e. via HTTP GET) for the login form
--
-- These are left for the user of the plugin to implement so that they can
-- retain control over form functionality, account models, email design and
-- email service provider.
--
-- Implementation checklist:
--
-- 1. Implement an instance of 'NoPasswordAuth' for your Yesod application.
-- 2. Implement a Yesod form that resolves to an 'EmailForm'.
-- 3. Add `authNoPassword` to your authentication plugins in your instance of
--    `YesodAuth`, passing the form you wish to use for authentication. This
--    typeclass provides a number of methods for customisation of behaviour,
--    but the minimal implementation is:
--
--     * 'loginRoute'
--     * 'emailSentRoute'
--     * 'sendLoginEmail'
--     * 'getUserByEmail'
--     * 'getEmailAndHashByTokenId'
--     * 'updateLoginHashForUser'
--     * 'newUserWithLoginHash'

module Yesod.Auth.NoPassword (
    -- * Plugin
      authNoPassword
    -- * Form Type
    , EmailForm(..)
    -- * Typeclass
    , NoPasswordAuth(..)
    -- * Types
    , Email
    , Token
    , TokenId
    , Hash
    -- ** Utility
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

-- | Route to which the site should POST the email form form.
loginPostR :: AuthRoute
loginPostR = PluginR pluginName ["login"]


type Email = Text
type Token = Text
type TokenId = Text
type Hash = Text


-- | Data type required for the Yesod form.
newtype EmailForm = EmailForm
    { efEmail :: Email
    }


-- Convenience alias for forms
type Form m a = (Html -> MForm (HandlerT m IO) (FormResult a, WidgetT m IO ()))


-- | Function to create the Yesod Auth plugin. Must be used by a type with an
-- instance for 'NoPasswordAuth', and must be given a form to use.
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
            strength <- lift $ tokenStrength
            (hash, token) <- liftIO $ genToken strength
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
    paramName <- lift tokenParamName
    loginParam <- lookupGetParam paramName
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
unpackTokenParam param = do
    p <- param
    case (splitOn ":" p) of
        (tid:tkn:[]) -> Just (tid, tkn)
        _ -> Nothing


genToken :: Int -> IO (Hash, Token)
genToken strength = do
    tokenSalt <- genSaltIO
    let token = exportSalt tokenSalt
    hash <- makePassword token strength
    return (decodeUtf8 hash, decodeUtf8 (urlEncode True token))


verifyToken :: Hash -> Token -> Bool
verifyToken hash token = verifyPassword t h
    where
        h = encodeUtf8 hash
        t = urlDecode False (encodeUtf8 token)


genTokenId :: IO TokenId
genTokenId = U.toText <$> U.nextRandom


genUrl :: NoPasswordAuth m => Token -> TokenId -> HandlerT Auth (HandlerT m IO) Text
genUrl token tid = do
    tm <- getRouteToParent
    render <- lift getUrlRender
    paramName <- lift tokenParamName
    let query = "?" <> paramName <> "=" <> tid <> ":" <> token
    return $ (render $ tm loginPostR) <> query


class YesodAuthPersist master => NoPasswordAuth master where
    -- | Route to a page that dispays a login form. This is not provided by
    -- the plugin.
    loginRoute :: master -> Route master

    -- | Route to which the user should be sent after entering an email
    -- address. This is not provided by the plugin.
    --
    -- __Note__: the user will not be authenticated when they reach the page.
    emailSentRoute :: master -> Route master

    -- | Send a login email.
    sendLoginEmail :: Email -- ^ The email to send to
                   -> Text  -- ^ The URL that will log the user in
                   -> HandlerT master IO ()

    -- | Get a user by their email address. Used to determine if the user exists or not.
    getUserByEmail :: Email -> HandlerT master IO (Maybe (AuthId master))

    -- | Get a Hash by a TokenId.
    --
    -- Invoked when the user returns to the site from an email. We don't know
    -- who the user is at this point as they may open the link from the email
    -- on another device or in another browser, so session data can't be used.
    -- Equally we do not want to pass the user's ID or email address in a URL
    -- if we don't have to, so instead we look up users by the 'TokenId' that
    -- we issued them earlier in the process.
    getEmailAndHashByTokenId :: TokenId -> HandlerT master IO (Maybe (Email, Hash))

    -- | Update a user's login hash
    --
    -- This is also used to blank out the hash once the user has logged in, or
    -- can be used to prevent the user from logging in, so must accept a value
    -- of `Nothing`.
    --
    -- /It is recommended that the/ 'TokenId' /storage be enforced as unique/.
    -- For this reason, the token is not passed as a maybe, as some storage
    -- backends treat `NULL` values as the same.
    updateLoginHashForUser :: (AuthId master) -> Maybe Hash -> TokenId -> HandlerT master IO ()

    -- | Create a new user with an email address and hash.
    newUserWithLoginHash :: Email -> Hash -> TokenId -> HandlerT master IO ()

    -- | __Optional__ – return a custom token strength.
    --
    -- A token strength of @x@ equates to @2^x@ hash rounds.
    tokenStrength :: HandlerT master IO Int
    tokenStrength = return 17

    -- | __Optional__ – return a custom token param name.
    tokenParamName :: HandlerT master IO Text
    tokenParamName = return "tkn"

    {-
        MINIMAL loginRoute
              , emailSentRoute
              , sendLoginEmail
              , getUserByEmail
              , getEmailAndHashByTokenId
              , updateLoginHashForUser
              , newUserWithLoginHash
    -}
