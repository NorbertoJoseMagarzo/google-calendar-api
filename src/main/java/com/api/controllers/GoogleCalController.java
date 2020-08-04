package com.api.controllers;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.view.RedirectView;

import com.google.api.client.auth.oauth2.AuthorizationCodeRequestUrl;
import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.auth.oauth2.TokenResponse;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeFlow;
import com.google.api.client.googleapis.auth.oauth2.GoogleClientSecrets;
import com.google.api.client.googleapis.auth.oauth2.GoogleClientSecrets.Details;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.googleapis.auth.oauth2.GoogleTokenResponse;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.client.util.DateTime;
import com.google.api.services.calendar.Calendar;
import com.google.api.services.calendar.Calendar.Events;
import com.google.api.services.calendar.CalendarScopes;
import com.google.api.services.calendar.model.Event;

@Controller
@CrossOrigin(origins = "*")
public class GoogleCalController {

	private final static Log logger = LogFactory.getLog(GoogleCalController.class);
	private static final String APPLICATION_NAME = "";
	private static HttpTransport httpTransport;
	private static final JsonFactory JSON_FACTORY = JacksonFactory.getDefaultInstance();
	private static com.google.api.services.calendar.Calendar client;

	GoogleClientSecrets clientSecrets;
	GoogleAuthorizationCodeFlow flow;
	Credential credential;

	@Value("${google.client.client-id}")
	private String clientId;
	@Value("${google.client.client-secret}")
	private String clientSecret;
	@Value("${google.client.redirectUri}")
	private String redirectURI;

	private Set<Event> events = new HashSet<>();

	final DateTime date1 = new DateTime("2017-05-05T16:30:00.000+05:30");
	final DateTime date2 = new DateTime(new Date());

	public void setEvents(Set<Event> events) {
		this.events = events;
	}

	@RequestMapping(value = "/login/google", method = RequestMethod.GET)
	public RedirectView googleConnectionStatus(HttpServletRequest request) throws Exception {
		return new RedirectView(authorize());
	}

	@RequestMapping(value = "/login/google", method = RequestMethod.GET, params = "code")
	public ResponseEntity<String> oauth2Callback(@RequestParam(value = "code") String code) {
		com.google.api.services.calendar.model.Events eventList;
		String message;
		String idToken = "Error al generar token";
		try {
			//4/2QHeu3PIT6Hk5EvpJTJUpOt5RsuTQKc9hf2yYh_rVMzJKgx8Dz7ttudnCJs8Xqnc9noW2BRq656FuewwzXLel7s
			TokenResponse response = flow.newTokenRequest(code).setRedirectUri(redirectURI).execute();
			testToken(response);
			
			////
			TokenResponse tokenResponseGenerated = new TokenResponse();
			//tokenResponseGenerated.set
			
			credential = flow.createAndStoreCredential(response, "userID");
			client = new com.google.api.services.calendar.Calendar.Builder(httpTransport, JSON_FACTORY, credential)
					.setApplicationName(APPLICATION_NAME).build();
			Events events = client.events();
			eventList = events.list("primary").setTimeMin(date1).setTimeMax(date2).execute();
			message = eventList.getItems().toString();
			idToken = response.get("id_token").toString();
			System.out.println("My:" + eventList.getItems());
		} catch (Exception e) {
			logger.warn("Exception while handling OAuth2 callback (" + e.getMessage() + ")."
					+ " Redirecting to google connection status page.");
			message = "Exception while handling OAuth2 callback (" + e.getMessage() + ")."
					+ " Redirecting to google connection status page.";
		}

		System.out.println("cal message:" + message);
		return new ResponseEntity<>(idToken, HttpStatus.OK);
	}

	public Set<Event> getEvents() throws IOException {
		return this.events;
	}

	private String authorize() throws Exception {
		AuthorizationCodeRequestUrl authorizationUrl;
		if (flow == null) {
			Details web = new Details();
			web.setClientId(clientId);
			web.setClientSecret(clientSecret);
			clientSecrets = new GoogleClientSecrets().setWeb(web);
			httpTransport = GoogleNetHttpTransport.newTrustedTransport();
			Collection<String> scopes = new ArrayList<String>();
			scopes.add(CalendarScopes.CALENDAR);
			scopes.add("https://www.googleapis.com/auth/userinfo.profile");
			scopes.add("https://www.googleapis.com/auth/userinfo.email");
			
			flow = new GoogleAuthorizationCodeFlow.Builder(httpTransport, JSON_FACTORY, clientSecrets,
					scopes).build();
		}
		authorizationUrl = flow.newAuthorizationUrl().setRedirectUri(redirectURI);
		System.out.println("cal authorizationUrl->" + authorizationUrl);
		
		
		return authorizationUrl.build();
	}
	
	private void testToken( TokenResponse response ){
		String accessToken = response.getAccessToken();
		String idToken = (String)response.get("id_token");
		
		JsonFactory JSON_FACTORY_TST = JacksonFactory.getDefaultInstance();
		String message;
		
		try {
			HttpTransport httpTransportTest = GoogleNetHttpTransport.newTrustedTransport();
			com.google.api.services.calendar.model.Events eventList;
	
		GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder(httpTransportTest, JSON_FACTORY_TST)
			    // Specify the CLIENT_ID of the app that accesses the backend:
			    .setAudience(Collections.singletonList(clientId))
			    // Or, if multiple clients access the backend:
			    //.setAudience(Arrays.asList(CLIENT_ID_1, CLIENT_ID_2, CLIENT_ID_3))
			    .build();

			// (Receive idTokenString by HTTPS POST)

				GoogleIdToken googleIdToken = GoogleIdToken.parse(JSON_FACTORY, idToken);
				boolean isValid = verifier.verify(googleIdToken);
				TokenResponse tr = new TokenResponse();
				tr.setAccessToken(accessToken);
				GoogleTokenResponse gtr = new GoogleTokenResponse();
				gtr.setIdToken(idToken);
				
				credential = flow.createAndStoreCredential(gtr, "userID");
				client = new com.google.api.services.calendar.Calendar.Builder(httpTransport, JSON_FACTORY, credential)
						.setApplicationName(APPLICATION_NAME).build();
				Events events = client.events();
				eventList = events.list("primary").setTimeMin(date1).setTimeMax(date2).execute();
				message = eventList.getItems().toString();
				
				
				
			} catch (GeneralSecurityException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		
	}
}