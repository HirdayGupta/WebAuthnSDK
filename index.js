export default function ZeroPass(apiKey) {
    this.key = apiKey
    this.register = function(user) {
        didClickRegister(user)
    }
}

function myResolve() {
    return {
        success: true
    }
}

function myReject() {
    return {
        success: false
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
        return console.error("Server validation of credential failed:", err);
    }

    // reload the page after a successful result
    // window.location.reload();
    // document.querySelector('#register_status').innerHTML = "User successfully registered!";

    console.log("success!")
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