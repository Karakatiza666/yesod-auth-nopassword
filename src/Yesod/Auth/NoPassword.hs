{-# LANGUAGE TypeFamilies #-}
--{-# LANGUAGE ExplicitForAll #-}
{-# LANGUAGE RankNTypes #-}
--{-# LANGUAGE PartialTypeSignatures #-}
--{-# LANGUAGE FlexibleContexts #-}
--{-# LANGUAGE ImpredicativeTypes #-}
{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}

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
--     * 'emailSentTarget'
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

import Data.Foldable (traverse_)
import Data.Monoid ((<>))
import Data.Text
import Data.Text.Encoding (encodeUtf8, decodeUtf8)
import qualified Text.Blaze as B

import qualified Data.UUID as U
import qualified Data.UUID.V4 as U

import Network.HTTP.Types.URI (urlEncode, urlDecode)
import Network.HTTP.Types.Status (badRequest400)

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
type Form master a = (Html -> MForm (HandlerFor master)  (FormResult a, WidgetFor master ()))
--type Form master a = forall m. master ~ HandlerSite m => (Html -> MForm m (FormResult a, WidgetFor master ()))

-- | Function to create the Yesod Auth plugin. Must be used by a type with an
-- instance for 'NoPasswordAuth', and must be given a form to use.
authNoPassword :: forall master m. (NoPasswordAuth master, HandlerFor master ~ m)
               => Form master EmailForm
               -> AuthPlugin master
authNoPassword form = AuthPlugin pluginName dispatch login
    where
        login _ = error "NoPasswordAuth does not provide a login widget"
        dispatch :: Text -> [Text] -> AuthHandler master TypedContent
        dispatch "POST" ["login"] = postEmailR form
        dispatch "GET"  ["login"] = getLoginR
        dispatch _ _ = notFound

postEmailR :: forall master m. (NoPasswordAuth master, HandlerFor master ~ m)
           => Form master EmailForm -> AuthHandler master TypedContent
postEmailR form = do
    ((result, _), _) <- liftHandler $ runFormPost form
    master <- liftHandler getYesod
    let msg = "Something went wrong, please try again"
    case (result, emailSentTarget master) of
        (FormMissing, Left route) -> do
            setMessage $ B.text msg
            liftHandler $ redirect route
        (FormMissing, Right errorResponse) ->
            liftHandler $ sendResponseStatus badRequest400 $ errorResponse [msg]
        (FormFailure as, Left route) -> do
            mapM_ (setMessage . B.text) as
            liftHandler $ redirect route
        (FormFailure as, Right errorResponse) ->
            liftHandler $ sendResponseStatus badRequest400 $ errorResponse as
        (FormSuccess e, Left route) -> do
            onFormSuccess e
            liftHandler $ redirect route
        (FormSuccess e, _) -> do
            onFormSuccess e
            sendResponse ()
    where
        onFormSuccess :: forall master m. (NoPasswordAuth master, HandlerFor master ~ m) =>
                         EmailForm -> AuthHandler master ()
        onFormSuccess e = do
            let email = efEmail e
            strength <- liftHandler tokenStrength
            (hash, token) <- liftIO $ genToken strength
            muser <- liftHandler $ getUserByEmail (efEmail e)
            tid <- liftIO genTokenId
            case muser of
                Just user ->
                    liftHandler $ updateLoginHashForUser user (Just hash) tid
                Nothing ->
                    liftHandler $ newUserWithLoginHash email hash tid
            referer <- liftHandler $ lookupGetParam =<< refererParamName
            url <- genUrl token tid referer
            liftHandler $ sendLoginEmail email url

getLoginR :: NoPasswordAuth master => AuthHandler master TypedContent
getLoginR = do
    loginParam <- lookupGetParam =<< liftHandler tokenParamName
    case unpackTokenParam loginParam of
        Nothing -> permissionDenied "Missing login token"
        Just (tid, loginToken) -> do
            muser <- liftHandler $ getEmailAndHashByTokenId tid
            case muser of
                Nothing -> permissionDenied "No login token sent"
                Just (email, hash) ->
                    if verifyToken hash loginToken
                        then liftHandler $ do
                            redirectTarget <- lookupGetParam =<< redirectParamName
                            traverse_ setUltDest redirectTarget
                            setCredsRedirect (Creds pluginName email [])
                        else permissionDenied "Incorrect login token"

unpackTokenParam :: Maybe Text -> Maybe (TokenId, Token)
unpackTokenParam param = do
    p <- param
    case splitOn ":" p of
        [tid,tkn] -> Just (tid, tkn)
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

genUrl :: NoPasswordAuth master => Token -> TokenId -> Maybe Text -> AuthHandler master Text
genUrl token tid referer = do
    tm <- getRouteToParent
    render <- liftHandler getUrlRender
    tokenName <- liftHandler tokenParamName
    redirectName <- liftHandler redirectParamName
    let refererParam = maybe "" (("&" <> redirectName <> "=") <>) referer
    let query = "?" <> tokenName <> "=" <> tid <> ":" <> token <> refererParam
    return $ render (tm loginPostR) <> query

class YesodAuthPersist master => NoPasswordAuth master where
    -- | Route to a page that dispays a login form. This is not provided by
    -- the plugin.
    loginRoute :: master -> Route master

    -- TODO: add deprecated function emailSentTarget that is replaced by emailSentTarget
    -- | EITHER: route to which the user should be sent after entering an email
    -- address. This is not provided by the plugin.
    -- OR: Function to make return value containing error messages should any occur.
    -- Then, in case of success simple HTTP status 200 will be returned
    -- and in case of error - HTTP bad request 400 with error value
    --
    -- __Note__: the user will not be authenticated when they reach the page.
    emailSentTarget :: master -> Either (Route master) ([Text] -> TypedContent)

    -- | Send a login email.
    sendLoginEmail :: Email -- ^ The email to send to
                   -> Text  -- ^ The URL that will log the user in
                   -> HandlerFor master ()

    -- | Get a user by their email address. Used to determine if the user exists or not.
    getUserByEmail :: Email -> HandlerFor master (Maybe (AuthId master))

    -- | Get a Hash by a TokenId.
    --
    -- Invoked when the user returns to the site from an email. We don't know
    -- who the user is at this point as they may open the link from the email
    -- on another device or in another browser, so session data can't be used.
    -- Equally we do not want to pass the user's ID or email address in a URL
    -- if we don't have to, so instead we look up users by the 'TokenId' that
    -- we issued them earlier in the process.
    getEmailAndHashByTokenId :: TokenId -> HandlerFor master (Maybe (Email, Hash))

    -- | Update a user's login hash
    --
    -- This is also used to blank out the hash once the user has logged in, or
    -- can be used to prevent the user from logging in, so must accept a value
    -- of `Nothing`.
    --
    -- /It is recommended that the/ 'TokenId' /storage be enforced as unique/.
    -- For this reason, the token is not passed as a maybe, as some storage
    -- backends treat `NULL` values as the same.
    updateLoginHashForUser :: AuthId master -> Maybe Hash -> TokenId -> HandlerFor master ()

    -- | Create a new user with an email address and hash.
    newUserWithLoginHash :: Email -> Hash -> TokenId -> HandlerFor master ()

    -- | __Optional__ – return a custom token strength.
    --
    -- A token strength of @x@ equates to @2^x@ hash rounds.
    tokenStrength :: HandlerFor master Int
    tokenStrength = return 17

    -- | __Optional__ – return a custom token param name.
    tokenParamName :: HandlerFor master Text
    tokenParamName = return "tkn"

    -- | __Optional__ – return a custom referer param name.
    refererParamName :: HandlerFor master Text
    refererParamName = return "referer"

    -- | __Optional__ – return a custom login redirect param name.
    redirectParamName :: HandlerFor master Text
    redirectParamName = return "redirect_to"

    {-# MINIMAL loginRoute
              , emailSentTarget
              , sendLoginEmail
              , getUserByEmail
              , getEmailAndHashByTokenId
              , updateLoginHashForUser
              , newUserWithLoginHash #-}
