/**
 * Copyright 2022 Inrupt Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the
 * Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

/* eslint-disable no-console */
global.Buffer = global.Buffer || require("buffer").Buffer;

if (typeof btoa === "undefined") {
  global.btoa = function (str) {
    return Buffer.from(str, "binary").toString("base64");
  };
}

if (typeof atob === "undefined") {
  global.atob = function (b64Encoded) {
    return new Buffer.from(b64Encoded, "base64").toString("binary");
  };
}

const { Session } = require("@inrupt/solid-client-authn-node");
const { config } = require("dotenv-flow");
const { fetch: crossFetch } = require("cross-fetch");
const express = require("express");
const {
  issueAccessRequest,
  redirectToAccessManagementUi,
  getFile,
  getAccessGrant,
} = require("@inrupt/solid-client-access-grants");

// Load env variables
config();

const app = express();
app.set("view engine", "ejs");
// Support parsing application/x-www-form-urlencoded
app.use(express.urlencoded({ extended: true }));

// This is the endpoint our NodeJS demo app listens on to receive incoming login
const redirectUrl = new URL("/redirect", process.env.APP_URL);
const REDIRECT_URL = redirectUrl.href;
const expirationDate = new Date(Date.now() + 180 * 6000);

app.get("/", async (req, res) => {
  res.render("index", { expirationDate });
});

app.post("/request", async (req, res) => {
  const session = new Session();
  await session.login({
    clientId: process.env.REQUESTOR_CLIENT_ID,
    clientSecret: process.env.REQUESTOR_CLIENT_SECRET,
    oidcIssuer: process.env.REQUESTOR_OIDC_ISSUER,
  });

  const accessRequest = await issueAccessRequest(
    {
      access: { read: true },
      purpose: ["https://some.purpose", "https://some.other.purpose"],
      requestor: session.info.webId,
      resourceOwner: req.body.owner,
      resources: [req.body.resource],
      expirationDate,
    },
    {
      fetch: session.fetch,
    }
  );
  await redirectToAccessManagementUi(accessRequest, REDIRECT_URL, {
    redirectCallback: (url) => {
      console.log(`redirecting to ${url}`);
      res.redirect(url);
    },
    // The following IRI redirects the user to PodBrowser so that they can approve/deny the request.
    fallbackAccessManagementUi: `https://podbrowser.inrupt.com/privacy/consent/requests/`,
    // Note: the following is only necessary because this projects depends for testing purpose
    // on solid-client-authn-browser, which is picked up automatically for convenience in
    // browser-side apps. A typical node app would not have this dependence.
    fetch: crossFetch,
  });
});

app.get("/redirect", async (req, res) => {
  const session = new Session();
  await session.login({
    clientId: process.env.REQUESTOR_CLIENT_ID,
    clientSecret: process.env.REQUESTOR_CLIENT_SECRET,
    oidcIssuer: process.env.REQUESTOR_OIDC_ISSUER,
    // Note that using a Bearer token is mandatory for the UMA access token to be valid.
    tokenType: "Bearer",
  });
  const { signedVcUrl } = req.query;
  const fullVc = await getAccessGrant(signedVcUrl, {
    fetch: session.fetch,
  });
  const decodedAccessGrant = fullVc;
  const targetResource =
    decodedAccessGrant.credentialSubject.providedConsent.forPersonalData[0];
  const file = await getFile(targetResource, decodedAccessGrant, {
    fetch: session.fetch,
  });
  const fileContent = await file.text();

  res.render("success", { fullVc: JSON.stringify(fullVc), fileContent });
});

app.listen(process.env.PORT, async () => {
  console.log(`Listening on [${process.env.PORT}]...`);
});
