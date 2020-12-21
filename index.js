const base64js = require("base64-js")

export default function ZeroPass(apiKey) {
    this.key = apiKey
    this.register = function(user) {
        return didClickRegister(user)
    }
    this.login = function(user) {
        return didClickLogin(user)
    }
}

function b64enc(buf) {
    return base64js.fromByteArray(buf)
                   .replace(/\+/g, "-")
                   .replace(/\//g, "_")
                   .replace(/=/g, "");
}

function b64RawEnc(buf) {
    return base64js.fromByteArray(buf)
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function hexEncode(buf) {
    return Array.from(buf)
                .map(function(x) {
                    return ("0" + x.toString(16)).substr(-2);
				})
                .join("");
}

async function fetch_json(url, options) {
    const BASE_URL = "https://api.zeropass.co/internal"
    let final_url = BASE_URL + url
    const response = await fetch(final_url, options);
    const body = await response.json();
    if (body.fail)
        throw body.fail;
    return body;
}

/**
 * REGISTRATION FUNCTIONS
 */

/**
 * Callback after the registration form is submitted.
 * @param {Event} e
 */


// GLOBAL STATE VARS:
let g_username = null;
let g_display_name = null;
let g_challenge = null;
let g_ukey = null;

const didClickRegister = async (user) => {

    // gather the data in the form
    // const form = document.querySelector('#register-form');
    // const formData = new FormData(form);
    // g_username = formData.get('username')
    // g_display_name = formData.get('display_name')

    const formData = new FormData()
    formData.set("username", user.username)
    formData.set("display_name", user.display_name)

    g_username = user.username
    g_display_name = user.display_name

    // post the data to the server to generate the PublicKeyCredentialCreateOptions
    let credentialCreateOptionsFromServer;
    try {
        credentialCreateOptionsFromServer = await getCredentialCreateOptionsFromServer(formData);
    } catch (err) {
        return console.error("Failed to generate credential request options:", err);
    }

    // convert certain members of the PublicKeyCredentialCreateOptions into
    // byte arrays as expected by the spec.
    const publicKeyCredentialCreateOptions = transformCredentialCreateOptions(credentialCreateOptionsFromServer);

    // request the authenticator(s) to create a new credential keypair.
    let credential;
    try {
        credential = await navigator.credentials.create({
            publicKey: publicKeyCredentialCreateOptions
        });
    } catch (err) {
        return console.error("Error creating credential:", err);
    }

    // we now have a new credential! We now need to encode the byte arrays
    // in the credential into strings, for posting to our server.
    const newAssertionForServer = transformNewAssertionForServer(credential);

    // post the transformed credential data to the server for validation
    // and storing the public key
    let assertionValidationResponse;
    try {
        assertionValidationResponse = await postNewAssertionToServer(newAssertionForServer);
    } catch (err) {
        throw new Error("Error registering the user!")
    }

    return {
        success: true
    }
}


/**
 * Get PublicKeyCredentialRequestOptions for this user from the server
 * formData of the registration form
 * @param {FormData} formData
 */
const getCredentialCreateOptionsFromServer = async (formData) => {
    let resp = await fetch_json(
        "/generate_registration_credentials",
        {
            method: "POST",
            body: formData
        }
    );
    console.log(resp);
    g_challenge = resp.challenge;
    g_ukey = resp.ukey;
    return resp.publicKeyCredentialCreationOptions;
}

/**
 * Transforms items in the credentialCreateOptions generated on the server
 * into byte arrays expected by the navigator.credentials.create() call
 * @param {Object} credentialCreateOptionsFromServer
 */
const transformCredentialCreateOptions = (credentialCreateOptionsFromServer) => {
    let {challenge, user} = credentialCreateOptionsFromServer;
    user.id = Uint8Array.from(
        atob(credentialCreateOptionsFromServer.user.id
            .replace(/\_/g, "/")
            .replace(/\-/g, "+")
            ),
        c => c.charCodeAt(0));

    challenge = Uint8Array.from(
        atob(credentialCreateOptionsFromServer.challenge
            .replace(/\_/g, "/")
            .replace(/\-/g, "+")
            ),
        c => c.charCodeAt(0));

    const transformedCredentialCreateOptions = Object.assign(
            {}, credentialCreateOptionsFromServer,
            {challenge, user});

    return transformedCredentialCreateOptions;
}

/**
 * Transforms the binary data in the credential into base64 strings
 * for posting to the server.
 * @param {PublicKeyCredential} newAssertion
 */
const transformNewAssertionForServer = (newAssertion) => {
    const attObj = new Uint8Array(
        newAssertion.response.attestationObject);
    const clientDataJSON = new Uint8Array(
        newAssertion.response.clientDataJSON);
    const rawId = new Uint8Array(
        newAssertion.rawId);

    const registrationClientExtensions = newAssertion.getClientExtensionResults();

    return {
        id: newAssertion.id,
        rawId: b64enc(rawId),
        type: newAssertion.type,
        attObj: b64enc(attObj),
        clientData: b64enc(clientDataJSON),
        registrationClientExtensions: JSON.stringify(registrationClientExtensions)
    };
}

/**
 * Posts the new credential data to the server for validation and storage.
 * @param {Object} credentialDataForServer
 */
const postNewAssertionToServer = async (credentialDataForServer) => {
    console.log(credentialDataForServer)
    const formData = new FormData();
    Object.entries(credentialDataForServer).forEach(([key, value]) => {
        formData.set(key, value);
    });
    // formData.set('ukey', g_ukey);
    // formData.set('challenge', g_challenge);
    // formData.set('publicKeyCredential', JSON.stringify(credentialDataForServer));
    console.log(formData)
    return await fetch_json(
        `/validate_registration_credentials?challenge=${g_challenge}&ukey=${g_ukey}&username=${g_username}&display_name=${g_display_name}`, {
        method: "POST",
        body: formData
    });
}

// Login User

const didClickLogin = async (user) => {
    // gather the data in the form
    const formData = new FormData()
    formData.set("username", user.username)

    // post the login data to the server to retrieve the PublicKeyCredentialRequestOptions
    let credentialRequestOptionsFromServer;
    try {
        credentialRequestOptionsFromServer = await getCredentialRequestOptionsFromServer(formData);
    } catch (err) {
        return console.error("Error when getting request options from server:", err);
    }

    // convert certain members of the PublicKeyCredentialRequestOptions into
    // byte arrays as expected by the spec.
    const transformedCredentialRequestOptions = transformCredentialRequestOptions(
        credentialRequestOptionsFromServer);

    // request the authenticator to create an assertion signature using the
    // credential private key
    let assertion;
    try {
        assertion = await navigator.credentials.get({
            publicKey: transformedCredentialRequestOptions,
        });
    } catch (err) {
        return console.error("Error when creating credential:", err);
    }

    // we now have an authentication assertion! encode the byte arrays contained
    // in the assertion data as strings for posting to the server
    const transformedAssertionForServer = transformAssertionForServer(assertion);

    // post the assertion to the server for verification.
    let response;
    try {
        response = await postAssertionToServer(transformedAssertionForServer);
    } catch (err) {
        throw new Error("Error logging in the user!")
    }


    return {
        success: true
    }
};

/**
 * Get PublicKeyCredentialRequestOptions for this user from the server
 * formData of the registration form
 * @param {FormData} formData
 */
const getCredentialRequestOptionsFromServer = async (formData) => {
    let resp = await fetch_json(
        "/generate_login_credentials",
        {
            method: "POST",
            body: formData
        }
    );
    console.log(resp);
    g_challenge = resp.challenge;
    return resp.publicKeyCredentialRequestOptions;
}

const transformCredentialRequestOptions = (credentialRequestOptionsFromServer) => {
    let {challenge, allowCredentials} = credentialRequestOptionsFromServer;

    challenge = Uint8Array.from(
        atob(challenge.replace(/\_/g, "/").replace(/\-/g, "+")), c => c.charCodeAt(0));

    allowCredentials = allowCredentials.map(credentialDescriptor => {
        let {id} = credentialDescriptor;
        id = id.replace(/\_/g, "/").replace(/\-/g, "+");
        id = Uint8Array.from(atob(id), c => c.charCodeAt(0));
        return Object.assign({}, credentialDescriptor, {id});
    });

    const transformedCredentialRequestOptions = Object.assign(
        {},
        credentialRequestOptionsFromServer,
        {challenge, allowCredentials});

    return transformedCredentialRequestOptions;
};



/**
 * Encodes the binary data in the assertion into strings for posting to the server.
 * @param {PublicKeyCredential} newAssertion
 */
const transformAssertionForServer = (newAssertion) => {
    const authData = new Uint8Array(newAssertion.response.authenticatorData);
    const clientDataJSON = new Uint8Array(newAssertion.response.clientDataJSON);
    const rawId = new Uint8Array(newAssertion.rawId);
    const sig = new Uint8Array(newAssertion.response.signature);
    const assertionClientExtensions = newAssertion.getClientExtensionResults();

    return {
        id: newAssertion.id,
        rawId: b64enc(rawId),
        type: newAssertion.type,
        authData: b64RawEnc(authData),
        clientData: b64RawEnc(clientDataJSON),
        signature: hexEncode(sig),
        assertionClientExtensions: JSON.stringify(assertionClientExtensions)
    };
};

/**
 * Post the assertion to the server for validation and logging the user in.
 * @param {Object} assertionDataForServer
 */
const postAssertionToServer = async (assertionDataForServer) => {
    const formData = new FormData();
    Object.entries(assertionDataForServer).forEach(([key, value]) => {
        formData.set(key, value);
    });

    return await fetch_json(
        `/validate_login_credentials?challenge=${g_challenge}`, {
        method: "POST",
        body: formData
    });
}