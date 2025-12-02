const puppeteer = require('puppeteer-core');
const os = require('node:os');
const { exec: execOrig } = require('node:child_process');
const { promisify } = require('node:util');
const path = require('node:path');
const which = require('which');
const { preferencesUtil } = require('../../store/preferences');
const { matchesCallbackUrl } = require('./authorize-user-utils');

const exec = promisify(execOrig);

const getDefaultBrowserExecutablePath = async () => {
  const platform = os.platform();
  if (platform === 'win32') {
    const httpHandlerCommand = String.raw`powershell.exe '(Get-ItemProperty -Path "Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice").ProgId'`;
    const progId = (await exec(httpHandlerCommand, { encoding: 'utf8' })).stdout.trim();

    const execPathCommand = String.raw`powershell.exe '(Get-ItemProperty -Path "Registry::HKEY_CLASSES_ROOT\\${progId}\shell\open\command")."(default)"'`;
    const execPath = (await exec(execPathCommand, { encoding: 'utf8' })).stdout.trim();

    const parsedExecPath = execPath.split('"')[1]; // Extract path from quotes

    return parsedExecPath;
  }
  if (platform === 'darwin') {
    // 1. Get bundle identifier for HTTP handler
    const { stdout } = await exec('defaults', [
      'read',
      'com.apple.LaunchServices/com.apple.launchservices.secure',
      'LSHandlers'
    ]);

    // `(?!-)` is to prevent matching `LSHandlerRoleAll = "-";`.
    const match = /LSHandlerRoleAll = "(?!-)(?<id>[^"]+?)";\s+?LSHandlerURLScheme = (?:http|https);/.exec(stdout);

    const bundleId = match?.groups.id;

    // 2. Find .app path using mdfind
    const appPath = exec(`mdfind "kMDItemCFBundleIdentifier == '${bundleId}'"`).toString().trim();
    if (!appPath) {
      throw new Error(`App path not found for bundle ID: ${bundleId}`);
    }

    // 3. Read CFBundleExecutable from Info.plist
    const executableName = exec(`/usr/libexec/PlistBuddy -c "Print :CFBundleExecutable" "${appPath}/Contents/Info.plist"`)
      .toString()
      .trim();

    // 4. Construct full executable path
    const execPath = path.join(appPath, 'Contents', 'MacOS', executableName);
    return execPath;
  }
  if (platform === 'linux') {
    const httpHandlerCommand = `xdg-mime query default x-scheme-handler/http`;
    const handlerDesktopFile = (await exec(httpHandlerCommand, { encoding: 'utf8' })).stdout.trim();

    return await which(handlerDesktopFile.replace('.desktop', ''));
  }
  throw new Error(`Unsupported platform: ${platform}`);
};

const authorizeUserInBrowser = ({
  authorizeUrl,
  callbackUrl,
  additionalHeaders = {},
  grantType = 'authorization_code',
  systemBrowserExecPath
}) => {
  return new Promise(async (resolve, reject) => {
    let finalUrl = null;
    let debugInfo = {
      data: []
    };
    let currentMainRequest = null;

    const executablePath = systemBrowserExecPath || await getDefaultBrowserExecutablePath();
    if (!executablePath) {
      return reject(new Error('Could not determine default browser executable path'));
    }

    try {
      const browser = await puppeteer.launch({
        headless: false,
        waitForInitialPage: false,
        executablePath,
        browser: executablePath.toLowerCase().includes('firefox') ? 'firefox' : 'chrome',
        // Ensure the browser window complies with "SSL/TLS Certificate Verification" preference
        acceptInsecureCerts: !preferencesUtil.shouldVerifyTls()
      });

      const page = (await browser.pages())[0];

      // Enable request interception
      await page.setRequestInterception(true);

      page.on('request', async (request) => {
        // onBeforeSendHeaders
        const currentHeaders = request.headers();

        if (Object.keys(additionalHeaders).length > 0) {
          // Add our custom headers
          for (const [name, value] of Object.entries(additionalHeaders)) {
            currentHeaders[name] = value;
          }
        }

        // This is a main frame request
        currentMainRequest = {
          request: {
            url: request.url(),
            method: request.method(),
            headers: currentHeaders,
            error: null
          },
          response: {
            headers: {},
            status: null,
            statusText: null,
            error: null
          },
          fromCache: false,
          completed: true,
          requests: [] // No sub-requests in this context
        };

        // Add to mainRequests

        // pushing the currentMainRequest to debugInfo
        // the currentMainRequest will be further updated by object reference
        debugInfo.data.push(currentMainRequest);

        try {
          // Continue the request unmodified
          await request.continue({
            headers: currentHeaders
          });

          const response = request.response();

          if (response) {
            currentMainRequest.response = {
              url: response.url(),
              method: response.request().method(),
              status: response.status(),
              headers: response.headers()
            };
            currentMainRequest.fromCache = response.fromCache();
            currentMainRequest.completed = true;
          }

          if (matchesCallbackUrl(new URL(request.url()), new URL(callbackUrl))) {
            finalUrl = request.url();
            await browser.close();
          }

          // Handle OAuth error responses
          const urlObj = new URL(request.url());
          if (urlObj.searchParams.has('error')) {
            const error = urlObj.searchParams.get('error');
            const errorDescription = urlObj.searchParams.get('error_description');
            const errorUri = urlObj.searchParams.get('error_uri');
            let errorData = {
              message: 'Authorization Failed!',
              error,
              errorDescription,
              errorUri
            };
            reject(new Error(JSON.stringify(errorData)));
            await browser.close();
          }
        } catch (error) {
          currentMainRequest.response.error = error;
        }
      });

      browser.on('disconnected', () => {
        if (finalUrl) {
          try {
            // Handle different grant types differently
            if (grantType === 'implicit') {
              // For implicit flow, tokens are in the URL hash fragment
              const urlWithHash = new URL(finalUrl);
              const hash = urlWithHash.hash.substring(1); // Remove the leading #
              const hashParams = new URLSearchParams(hash);

              // Extract tokens from hash fragment
              const implicitTokens = {
                access_token: hashParams.get('access_token'),
                token_type: hashParams.get('token_type'),
                expires_in: hashParams.get('expires_in'),
                state: hashParams.get('state'),
                scope: hashParams.get('scope')
              };

              return resolve({ implicitTokens, debugInfo });
            } else {
              // Default case - authorization code flow
              const callbackUrlWithCode = new URL(finalUrl);
              const authorizationCode = callbackUrlWithCode.searchParams.get('code');
              return resolve({ authorizationCode, debugInfo });
            }
          } catch (error) {
            return reject(error);
          }
        } else {
          return reject(new Error('Authorization window closed'));
        }
      });

      // Example navigation
      await page.goto(authorizeUrl, { waitUntil: 'networkidle2' });
    } catch (error) {
      return reject(error);
    }
  });
};

module.exports = { authorizeUserInBrowser };
