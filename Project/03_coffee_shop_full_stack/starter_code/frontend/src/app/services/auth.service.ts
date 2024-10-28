import { Injectable } from "@angular/core";
import { JwtHelperService } from "@auth0/angular-jwt";

import { environment } from "../../environments/environment";
import { BehaviorSubject, Observable, of } from "rxjs";

const JWTS_LOCAL_KEY = "JWTS_LOCAL_KEY";

@Injectable({
  providedIn: "root",
})
export class AuthService {
  url = environment.auth0.url;
  audience = environment.auth0.audience;
  clientId = environment.auth0.clientId;
  callbackURL = environment.auth0.callbackURL;

  token: string;
  payload: any;

  jwtHelper = new JwtHelperService();

  constructor() {}

  build_login_link(callbackPath = "") {
    let link = "https://";
    link += this.url + ".auth0.com";
    link += "/authorize?";
    link += "audience=" + this.audience + "&";
    link += "response_type=token&";
    link += "client_id=" + this.clientId + "&";
    link += "redirect_uri=" + this.callbackURL + callbackPath;
    return link;
  }

  // invoked in app.component on load
  check_token_fragment() {
    // parse the fragment
    const fragment = window.location.hash.substr(1).split("&")[0].split("=");
    // check if the fragment includes the access token
    if (fragment[0] === "access_token") {
      // add the access token to the jwt
      this.token = fragment[1];
      // save jwts to localstore
      this.set_jwt();
    }
  }

  set_jwt() {
    localStorage.setItem(JWTS_LOCAL_KEY, this.token);
    if (this.token) {
      this.decodeJWT(this.token);
    }
  }

  load_jwts() {
    this.token = this.getToken() || null;
    if (this.token) {
      this.decodeJWT(this.token);
    }
  }

  activeJWT() {
    return this.token;
  }

  decodeJWT(token: string) {
    const jwtservice = new JwtHelperService();
    this.payload = jwtservice.decodeToken(token);
    return this.payload;
  }

  logout() {
    this.token = null;
    this.payload = null;
    localStorage.removeItem(JWTS_LOCAL_KEY);
  }

  login() {
    const link = this.build_login_link();
    window.location.href = link;
    return;
  }

  can(permission: string) {
    return (
      this.payload &&
      this.payload.permissions &&
      this.payload.permissions.length &&
      this.payload.permissions.indexOf(permission) >= 0
    );
  }

  isAuthenticated(): boolean {
    const token = this.getToken() || null;
    return token ? !this.jwtHelper.isTokenExpired(token) : false;
  }

  getToken(): string | null {
    return localStorage.getItem(JWTS_LOCAL_KEY);
  }
}
