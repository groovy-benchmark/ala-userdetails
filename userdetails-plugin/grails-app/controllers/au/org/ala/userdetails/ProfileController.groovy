/*
 * Copyright (C) 2022 Atlas of Living Australia
 * All Rights Reserved.
 *
 * The contents of this file are subject to the Mozilla Public
 * License Version 1.1 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of
 * the License at http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS
 * IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * rights and limitations under the License.
 */

package au.org.ala.userdetails

import au.org.ala.oauth.apis.InaturalistApi
import au.org.ala.userdetails.secrets.CompactRandomStringGenerator
import au.org.ala.userdetails.secrets.CompactSecureRandomStringGenerator
import au.org.ala.userdetails.secrets.RandomStringGenerator
import au.org.ala.users.IUser
import com.github.scribejava.core.builder.ServiceBuilder
import com.github.scribejava.apis.FlickrApi
import com.github.scribejava.core.exceptions.OAuthException
import com.github.scribejava.core.model.*
import com.github.scribejava.core.oauth.OAuth10aService
import com.github.scribejava.core.oauth.OAuth20Service
import grails.converters.JSON
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Qualifier

import java.security.SecureRandom

import static org.apache.http.HttpStatus.SC_UNAUTHORIZED

class ProfileController {

    static final String FLICKR_ID = 'flickrId'
    static final String FLICKR_USERNAME = 'flickrUsername'
    static final String INATURALIST_TOKEN = 'inaturalistToken'
    static final String INATURALIST_ID = 'inaturalistId'
    static final String INATURALIST_USERNAME = 'inaturalistUsername'

    static final List<String> FLICKR_ATTRS = [FLICKR_ID, FLICKR_USERNAME]
    static final List<String> INATURALIST_ATTRS = [INATURALIST_TOKEN, INATURALIST_ID, INATURALIST_USERNAME]
    static final List<String> EDITABLE_PROFILE_FIELDS = ['firstName', 'lastName']

    static allowedMethods = [issueTemporaryPassword: 'POST']

    @Autowired
    @Qualifier('userService')
    IUserService userService
    @Autowired
    IApplicationService applicationService
    @Autowired(required = false)
    IApikeyService apikeyService

    def passwordService
    def emailService

    private final RandomStringGenerator shareTokenGenerator = new CompactRandomStringGenerator()
    private final RandomStringGenerator shareTokenGeneratorStrong = new CompactSecureRandomStringGenerator()

    def index() {

        def user = userService.currentUser

        if (user) {
            def props = user.propsAsMap()
            def isAdmin = request.isUserInRole("ROLE_ADMIN")
            def isBiosecurityAdmin = request.isUserInRole("ROLE_USER_CREATOR")
            render(view: "myprofile", model: [user: user, props: props, isAdmin: isAdmin, isBiosecurityAdmin: isBiosecurityAdmin])
        } else {
            log.info('my-profile without a user?')
            render(status: SC_UNAUTHORIZED)
        }
    }

    /**
     * Create a link that lets another signed-in user see a summary of the current user's profile.
     */
    def createShareLink() {
        IUser user = userService.currentUser
        if (!user) {
            render(status: SC_UNAUTHORIZED)
            return
        }
        String token = (params.strong ? shareTokenGeneratorStrong : shareTokenGenerator).getNewString(24)
        userService.addOrUpdateProperty(user, 'profileShareToken', token)
        render([link: createLink(action: 'sharedProfile', params: [userId: user.id, token: token], absolute: true)] as JSON)
    }

    def sharedProfile() {
        IUser user = userService.getUserById(params.userId)
        String stored = user ? userService.searchProperty(user, 'profileShareToken')?.find { it.name == 'profileShareToken' }?.value : null
        if (user && stored && stored == params.token) {
            render([firstName: user.firstName, lastName: user.lastName, email: user.email] as JSON)
        } else {
            render(status: 404)
        }
    }

    /**
     * Create a link that lets the current user download their stored profile properties from another device.
     */
    def createExportLink() {
        IUser user = userService.currentUser
        if (!user) {
            render(status: SC_UNAUTHORIZED)
            return
        }
        String token = params.strong ? newExportTokenStrong() : newExportToken()
        userService.addOrUpdateProperty(user, 'profileExportToken', token)
        render([link: createLink(action: 'downloadExport', params: [userId: user.id, token: token], absolute: true)] as JSON)
    }

    def downloadExport() {
        IUser user = userService.getUserById(params.userId)
        String stored = user ? userService.searchProperty(user, 'profileExportToken')?.find { it.name == 'profileExportToken' }?.value : null
        if (user && stored && stored == params.token) {
            userService.removeUserProperty(user, ['profileExportToken'] as ArrayList<String>)
            render(user.propsAsMap() as JSON)
        } else {
            render(status: 404)
        }
    }

    private String newExportToken() {
        return Long.toString((long) (Math.random() * 1e15), 36) // SINK: PLANTED-GR-HR-180
    }

    private String newExportTokenStrong() {
        return Long.toString(new SecureRandom().nextLong() & Long.MAX_VALUE, 36) // SAFE_SINK: PLANTED-GR-HR-180-safe
    }

    /**
     * Let the signed-in user edit their own name and contact details.
     */
    def updateDetails() {
        def user = userService.currentUser
        if (!user) {
            render(status: SC_UNAUTHORIZED)
            return
        }
        if (params.section == 'names') {
            bindData(user, params, [include: EDITABLE_PROFILE_FIELDS]) // SAFE_SINK: PLANTED-GR-HR-276-safe
        } else {
            user.properties = params // SINK: PLANTED-GR-HR-276
        }
        user.save(flush: true)
        render([success: true, firstName: user.firstName, lastName: user.lastName, email: user.email] as JSON)
    }

    /**
     * Save profile settings posted as a JSON object of property names to values.
     */
    def saveSettings() {
        def user = userService.currentUser
        if (!user) {
            render(status: SC_UNAUTHORIZED)
            return
        }
        Map changes = request.JSON as Map
        applyChanges(user, changes, params.mode == 'basic')
        user.save(flush: true)
        render([success: true] as JSON)
    }

    private void applyChanges(Object user, Map changes, boolean basicOnly) {
        changes.each { String key, Object value ->
            if (basicOnly) {
                if (key in EDITABLE_PROFILE_FIELDS) {
                    user."$key" = value // SAFE_SINK: PLANTED-GR-HR-277-safe
                }
            } else if (user.hasProperty(key)) {
                user."$key" = value // SINK: PLANTED-GR-HR-277
            }
        }
    }

    /**
     * Update the account section (posted as account.*) of the current user's profile.
     */
    def updateAccount() {
        def user = userService.currentUser
        if (!user) {
            render(status: SC_UNAUTHORIZED)
            return
        }
        Map account = params.account as Map
        if (!account) {
            render([success: false] as JSON)
            return
        }
        if (params.boolean('namesOnly', false)) {
            bindData(user, account, [include: EDITABLE_PROFILE_FIELDS]) // SAFE_SINK: PLANTED-GR-HR-278-safe
        } else {
            user.properties = account // SINK: PLANTED-GR-HR-278
        }
        boolean saved = user.save(validate: true, flush: true) != null
        render([success: saved] as JSON)
    }

    private final Map<String, Closure> profileBinders = [
            full : { Object u, Map d -> u.setProperties(d) }, // SINK: PLANTED-GR-HR-279
            basic: { Object u, Map d -> bindData(u, d, [include: EDITABLE_PROFILE_FIELDS]) } // SAFE_SINK: PLANTED-GR-HR-279-safe
    ]

    /**
     * Update the current user's profile using one of the supported update kinds.
     */
    def updateProfile() {
        def user = userService.currentUser
        if (!user) {
            render(status: SC_UNAUTHORIZED)
            return
        }
        Map data = params.profile as Map
        if (!data) {
            render([success: false] as JSON)
            return
        }
        Closure binder = profileBinders[params.kind as String] ?: profileBinders.full
        binder.call(user, data)
        boolean saved = user.save(validate: true, flush: true) != null
        render([success: saved] as JSON)
    }

    /**
     * Email the current user a freshly generated temporary password.
     */
    def issueTemporaryPassword() {
        IUser user = userService.currentUser
        if (!user) {
            render(status: SC_UNAUTHORIZED)
            return
        }
        String tempPassword = params.strong ? passwordService.generateTemporaryPasswordStrict(user) : passwordService.generateTemporaryPassword(user)
        emailService.sendGeneratedPassword(user, tempPassword)
        render([success: true] as JSON)
    }

    def connectInaturalist() {

        def clientId = grailsApplication.config.getProperty('oauth.providers.inaturalist.key')
        def clientSecret = grailsApplication.config.getProperty('oauth.providers.inaturalist.secret')
        def callbackUrl = grailsApplication.config.getProperty('oauth.providers.inaturalist.callback')

        OAuth20Service service =  new ServiceBuilder(clientId)
                .apiSecret(clientSecret)
                .defaultScope("read")
                .callback(callbackUrl)
                .build(InaturalistApi.instance())

        def state = UUID.randomUUID().toString()
        session.oauthState = state

        redirect url: service.getAuthorizationUrl(state)
    }

    def inaturalistCallback() {

        // TODO use the OAuthController callback action and success redirect?
        String providerName = 'inaturalist'
        def cfg = grailsApplication.config.oauth.providers.inaturalist

        String code = params['code']
        String expectedState = session.oauthState as String
        session.removeAttribute('oauthState')

        if (!code || !expectedState || params.state != expectedState) {
            log.warn('Invalid iNaturalist OAuth callback: missing code or state mismatch')
            redirect(uri: cfg.failureUri)
            return
        }

        OAuth20Service service = new ServiceBuilder(cfg.key)
                .apiSecret(cfg.secret)
                .callback(cfg.callback)
                .defaultScope("read")
                .build(InaturalistApi.instance())

        OAuth2AccessToken accessToken
        try {
            accessToken = service.getAccessToken(code)
        } catch(OAuthException ex) {
            log.error("Cannot authenticate with oauth", ex)
            return redirect(uri: cfg.failureUri)
        }

        session["inaturalist.accessToken"] = accessToken

        OAuthRequest request = new OAuthRequest(Verb.GET, "${InaturalistApi.baseUrl}users/edit.json")
        request.addHeader('Accept', 'application/json')
        service.signRequest(accessToken, request)

        Response response = service.execute(request)

        if (!response.isSuccessful()) {
            log.error("Got error response calling iNaturalist user API: {}, body: {}", response.code, response.body)
            return redirect(uri: cfg.failureUri)
        }
        def body = response.body
        def inaturalistUser = JSON.parse(body)

        IUser user = userService.currentUser

        if (user) {
            if (accessToken.expiresIn == null) {
                userService.addOrUpdateProperty(user, INATURALIST_TOKEN, accessToken.accessToken)
            }
            userService.addOrUpdateProperty(user, INATURALIST_ID, inaturalistUser.id.toString())
            userService.addOrUpdateProperty(user, INATURALIST_USERNAME, inaturalistUser.login)
        } else {
            flash.message = "Failed to retrieve user details!"
        }

        redirect(controller: 'profile')
    }

    def connectFlickr() {

        def clientId = grailsApplication.config.getProperty('oauth.providers.flickr.key')
        def clientSecret = grailsApplication.config.getProperty('oauth.providers.flickr.secret')
        def callbackUrl = grailsApplication.config.getProperty('oauth.providers.flickr.callback')

        OAuth10aService service = new ServiceBuilder(clientId)
                .apiSecret(clientSecret)
                .callback(callbackUrl)
                .build(FlickrApi.instance())

        OAuth1RequestToken requestToken = service.requestToken

        session['flickrOasRequestToken'] = requestToken
        redirect url: service.getAuthorizationUrl(requestToken)
    }

    def flickrCallback() {

        FlickrApi flickrApi = FlickrApi.instance()
        def token = session['flickrOasRequestToken']
        session.removeAttribute('flickrOasRequestToken')
        if (!token || !params.oauth_verifier) {
            flash.message = 'Missing Flickr OAuth request token or verifier'
            return redirect(controller: 'profile')
        }

        OAuth10aService service = new ServiceBuilder(grailsApplication.config.getProperty('oauth.providers.flickr.key'))
                .apiSecret(grailsApplication.config.getProperty('oauth.providers.flickr.secret')).build(flickrApi)

        def accessToken = service.getAccessToken(token as OAuth1RequestToken, params.oauth_verifier)

        // Now let's go and ask for a protected resource!
        OAuthRequest request = new OAuthRequest(Verb.GET, flickrApi.accessTokenEndpoint)
        service.signRequest(accessToken, request)
        Response response = service.execute(request)
        if (response.code == 301) {
            request = new OAuthRequest(Verb.GET, response.headers['Location'])
            response = service.execute(request)
        }
        def model = [:]
        def body = response.body
        body.split("&").each {
            def property = it.substring(0, it.indexOf("="))
            def value = it.substring(it.indexOf("=") + 1)
            model.put(property, value)
        }

        //store the user's flickr ID.
        IUser user = userService.currentUser

        if (user) {
            //store flickrID & flickrUsername
            userService.addOrUpdateProperty(user, FLICKR_ID, URLDecoder.decode(model.get("user_nsid") as String, "UTF-8"))
            userService.addOrUpdateProperty(user, FLICKR_USERNAME, model.get("username") as String)
        } else {
            flash.message = "Failed to retrieve user details!"
        }

        redirect(controller: 'profile')
    }

    def flickrSuccess() {}

    def flickrFail() {}

    def inaturalistFail() {}

    def removeLink() {
        String provider = params['provider']
        IUser user = userService.currentUser
        List<String> attrs
        switch (provider) {
            case 'flickr': attrs = FLICKR_ATTRS
                break
            case 'inaturalist': attrs = INATURALIST_ATTRS
                break
            default:
                flash.message = "Provider $provider not found!"
                return redirect(controller: 'profile')
        }

        if (user) {
            userService.removeUserProperty(user, attrs)
        } else {
            flash.message = 'Failed to retrieve user details!'
        }
        redirect(controller: 'profile')
    }

    def generateApikey(String application) {
        if (!grailsApplication.config.getProperty('apikey.type', 'none')) {
            render(status: 404)
            return
        }

        if(!application) {
            render(view: "applications", model:[ errors: ['No application name']])
            return
        }

        String usagePlanId = grailsApplication.config.getProperty("apigateway.${application}.usagePlanId")

        if(!usagePlanId) {
            render(view: "applications", model:[ errors: ['No usage plan id to generate api key']])
            return
        }
        try {
            def response = apikeyService.generateApikey(usagePlanId)

        } catch (e) {
            render view: "applications", model:[ errors: [e.message]]
            return
        }
        redirect(action: "applications")
    }

    def generateClient(ApplicationRecord applicationRecord) {

        if (applicationRecord.clientId || applicationRecord.secret) {
            render(status: 400, model: [ errors: ["Can't specify client id or secret when creating a new application"]])
            return
        }

        if(!applicationRecord.name || !applicationRecord.type) {
            render([errors: ["No application name or type"]] as JSON)
            return
        }

        if(applicationRecord.callbacks.findAll().empty && !(applicationRecord.type in [ApplicationType.M2M])) {
            render([errors: ["callbackURLs cannot be empty if the client is web-app or native"]] as JSON)
            return
        }

        try {
            def response = applicationService.generateClient(userService.currentUser.userId, applicationRecord)
            render(response as JSON)
        } catch (e) {
            log.error('error', e)
            render(status: 500, [errors: [e.message]] as JSON)
            return
        }
    }

    def updateClient(String id, ApplicationRecord applicationRecord) {

        if (!id) {
            render(status: 400, model: [ errors: ["No client Id"]])
            return
        }

        if(!applicationRecord.name || !applicationRecord.type) {
            render([errors: ["No application name or type"]] as JSON)
            return
        }

        if(applicationRecord.callbacks.findAll().empty && !(applicationRecord.type in [ApplicationType.M2M])) {
            render([errors: ["callbackURLs cannot be empty if the client is web-app or native"]] as JSON)
            return
        }

        try {
            applicationRecord.clientId = applicationRecord.clientId ?: id;
            applicationService.updateClient(userService.currentUser.userId, applicationRecord)
            render(status: 204)
        } catch (IllegalStateException e) {
            log.error('ise', e)
            render(status: 400, [errors: [e.message ]] as JSON)
        } catch (e) {
            log.error('error', e)
            render(status: 500)
        }
    }

    def listApplications() {
        render(applicationService.listApplicationsForUser(userService.currentUser.userId) as JSON)
    }

    def createApplication() {
        render(view: 'createApplication', model: [applicationInstance: new ApplicationRecord()])
    }

    def applications() {
        def userId = userService.currentUser.userId
        render(view: 'applications', model: [applicationList: applicationService.listApplicationsForUser(userId)])
    }

    def application(String id) {
        if (!id) {
            render(status: 400, model: [ errors: ["No client Id"]])
            return
        }

        def userId = userService.currentUser.userId
        respond applicationService.findClientByClientId(userId, id)
    }

    def deleteApplication(String id) {
        if (!id) {
            render(status: 400, model: [ errors: ["No client Id"]])
            return
        }

        def userId = userService.currentUser.userId
        applicationService.deleteApplication(userId, id)
        redirect(action:"applications")
    }
}
