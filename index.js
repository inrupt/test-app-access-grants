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

const path = require("path");
const { Session } = require("@inrupt/solid-client-authn-node");
const { config } = require("dotenv-flow");
const { fetch: crossFetch } = require("cross-fetch");
const express = require("express");
const {
  issueAccessRequest,
  redirectToAccessManagementUi,
  getFile,
  getAccessGrant,
  GRANT_VC_URL_PARAM_NAME,
} = require("@inrupt/solid-client-access-grants");

// Load env variables
config();

const app = express();

app.set("view engine", "ejs");

app.set("views", path.join(__dirname, "views"));

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
      purpose: [
        "https://w3c.github.io/dpv/dpv/#UserInterfacePersonalisation",
        "https://w3c.github.io/dpv/dpv/#OptimiseUserInterface",
      ],
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
    fallbackAccessManagementUi: `https://podbrowser.inrupt.com/privacy/access/requests/`,
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
  const accessGrantUrl = req.query[GRANT_VC_URL_PARAM_NAME];
  const fullVc = await getAccessGrant(accessGrantUrl, {
    fetch: session.fetch,
  });
  const decodedAccessGrant = fullVc;
  const targetResource =
    decodedAccessGrant.credentialSubject.providedConsent.forPersonalData[0];
  let fileContent;
  try {
    const file = await getFile(targetResource, decodedAccessGrant, {
      fetch: session.fetch,
    });
    fileContent = await file.text();
  } catch (e) {
    // ignoring the error since it is expected that fetching fails for a
    // resource with a denied access grant - in the future we want to provide
    // feedback to users when errors are due to other reasons
    console.log(e);
  } finally {
    res.render("success", {
      fullVc: JSON.stringify(fullVc, null, 2),
      fileContent,
      resourceUrl: targetResource,
    });
  }
});

app.listen(process.env.PORT, async () => {
  console.log(`Listening on [${process.env.PORT}]...`);
});
