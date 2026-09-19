;;; mcp-oauth.el --- OAuth support for MCP clients -*- lexical-binding: t; -*-

;; Copyright (C) 2026 cat-emacs
;; SPDX-License-Identifier: GPL-3.0-or-later

;;; Commentary:
;; Provider-neutral OAuth 2.1 device authorization support for remote MCP.
;; PKCE loopback authorization-code flow is intentionally not implemented here.

;;; Code:

(require 'cl-lib)
(require 'json)
(require 'rx)
(require 'seq)
(require 'subr-x)
(require 'url)
(require 'url-http)
(require 'url-util)

(defvar url-http-end-of-headers)
(defvar url-max-redirections)
(defvar url-http-response-status)

(defgroup mcp-oauth nil
  "OAuth support for MCP clients."
  :group 'mcp)

(defcustom mcp-oauth-storage-directory
  (locate-user-emacs-file "mcp-oauth/")
  "Directory containing per-resource OAuth state files."
  :type 'directory)

(defcustom mcp-oauth-expiry-skew 60
  "Seconds before expiry at which an access token is refreshed."
  :type 'integer)

(cl-defstruct (mcp-oauth-provider
               (:constructor mcp-oauth-provider-create))
  resource config metadata authorization-server client state poll-timer waiters)

(defun mcp-oauth--config (provider key)
  "Return KEY from PROVIDER configuration."
  (plist-get (mcp-oauth-provider-config provider) key))

(defun mcp-oauth--allow-http-p (provider)
  "Return whether PROVIDER explicitly permits insecure HTTP."
  (mcp-oauth--config provider :allow-http))

(defun mcp-oauth--https-url-p (provider url)
  "Return non-nil when URL is an allowed absolute HTTP URL."
  (let ((parsed (url-generic-parse-url url)))
    (and (url-host parsed)
         (or (string= (url-type parsed) "https")
             (and (mcp-oauth--allow-http-p provider)
                  (string= (url-type parsed) "http"))))))

(defun mcp-oauth--require-url (provider url label)
  "Validate PROVIDER URL labelled LABEL and return it."
  (unless (and (stringp url) (mcp-oauth--https-url-p provider url))
    (error "%s must be an absolute HTTPS URL" label))
  url)

(defun mcp-oauth--resource-uri (provider url)
  "Return canonical RFC 8707 resource URI for PROVIDER URL.
The path and query are preserved because they can identify distinct resources.
Fragments are not valid RFC 8707 resource indicators."
  (mcp-oauth--require-url provider url "OAuth resource")
  (let* ((parsed (url-generic-parse-url url))
         (scheme (downcase (url-type parsed)))
         (host (downcase (url-host parsed)))
         (port (url-port parsed))
         (path (or (url-filename parsed) "/"))
         (fragment (url-target parsed)))
    (when fragment
      (error "OAuth resource URI must not contain a fragment"))
    (format "%s://%s%s%s"
            scheme host
            (if (and port
                     (not (or (and (string= scheme "https") (= port 443))
                              (and (string= scheme "http") (= port 80)))))
                (format ":%d" port)
              "")
            (if (string-empty-p path) "/" path))))

(defun mcp-oauth--safe-id (string)
  "Return a stable file-safe identifier for STRING."
  (secure-hash 'sha256 string))

(defun mcp-oauth--state-file (provider)
  "Return PROVIDER state file path."
  (expand-file-name
   (concat (mcp-oauth--safe-id (mcp-oauth-provider-resource provider)) ".json")
   (or (mcp-oauth--config provider :storage-directory)
       mcp-oauth-storage-directory)))

(defun mcp-oauth--json (string label)
  "Parse STRING as JSON for LABEL, or signal a safe error."
  (condition-case err
      (json-parse-string string :object-type 'plist :array-type 'array
                         :null-object nil :false-object :json-false)
    (json-parse-error
     (error "Invalid OAuth JSON from %s: %s" label (error-message-string err)))))

(defun mcp-oauth--redact (value)
  "Redact OAuth secrets in VALUE for safe diagnostics."
  (let ((text (format "%s" value))
        (key "\\(?:access_token\\|refresh_token\\|client_secret\\|device_code\\|code\\)"))
    (setq text (replace-regexp-in-string
                (concat "\\([\"']?" key "[\"']?\\)[[:space:]]*[:=][[:space:]]*\\(?:[\"'][^\"']*[\"']\\|[^,[:space:]}]+\\)")
                "\\1=[REDACTED]" text t))
    (replace-regexp-in-string
     "\\(Authorization:[[:space:]]*Bearer[[:space:]]+\\)[^[:space:],]+"
     "\\1[REDACTED]" text t)))

(defun mcp-oauth--bearer-response-p ()
  "Return non-nil when the current HTTP response has a Bearer challenge."
  (let ((case-fold-search t))
    (cl-some
     (lambda (header)
       (string-match-p
        (rx (or string-start ",") (* blank) "Bearer" (or blank string-end))
        header))
     (mcp-oauth--headers
      (buffer-substring-no-properties
       (point-min)
       (or (and (boundp 'url-http-end-of-headers)
                (integer-or-marker-p url-http-end-of-headers)
                url-http-end-of-headers)
           (point-max)))
      "WWW-Authenticate"))))

(defun mcp-oauth--http (provider method url headers data)
  "Issue synchronous OAuth HTTP request and return (STATUS HEADERS BODY).
This narrow seam is intentionally easy to mock in ERT tests."
  (mcp-oauth--require-url provider url "OAuth endpoint")
  (let* ((url-request-method method)
         (url-request-extra-headers headers)
         (url-request-data data)
         ;; OAuth endpoints must never redirect credentials or device codes.
         (url-max-redirections 0)
         (original-auth-handler
          (symbol-function 'url-http-handle-authentication))
         (buffer
          (cl-letf (((symbol-function 'url-http-handle-authentication)
                     (lambda (proxy)
                       ;; Emacs treats every 401 as Basic/Digest authentication.
                       ;; Preserve Bearer challenges for OAuth discovery instead.
                       (if (and (not proxy) (mcp-oauth--bearer-response-p))
                           t
                         (funcall original-auth-handler proxy)))))
            (url-retrieve-synchronously url t t 30))))
    (unless buffer (error "OAuth request timed out"))
    (unwind-protect
        (with-current-buffer buffer
          (let ((status url-http-response-status)
                (end url-http-end-of-headers))
            (unless (and (integerp status) end) (error "Invalid OAuth HTTP response"))
            (list status
                  (buffer-substring-no-properties (point-min) end)
                  (buffer-substring-no-properties end (point-max)))))
      (kill-buffer buffer))))

(defun mcp-oauth--form (pairs)
  "Encode PAIRS as application/x-www-form-urlencoded data."
  (mapconcat (lambda (pair)
               (concat (url-hexify-string (car pair)) "="
                       (url-hexify-string (format "%s" (cdr pair)))))
             (cl-remove-if (lambda (pair) (null (cdr pair))) pairs) "&"))

(defun mcp-oauth--request-json (provider method url headers data label)
  "Request successful JSON from URL or signal a generic safe error."
  (pcase-let ((`(,status ,_headers ,body)
               (mcp-oauth--http provider method url headers data)))
    (unless (<= 200 status 299)
      (if (<= 300 status 399)
          (error "OAuth %s failed: redirect refused" label)
        (error "OAuth %s failed (%d)" label status)))
    (mcp-oauth--json body label)))

;;;###autoload
(defun mcp-oauth-create (resource &optional config)
  "Create an OAuth provider for MCP RESOURCE using CONFIG plist.
CONFIG accepts :client-name, :scopes, :metadata-url, :authorization-server,
:static-client, :storage-directory, :allow-http and :open-browser."
  (let ((provider (mcp-oauth-provider-create
                   :resource nil :config config)))
    (setf (mcp-oauth-provider-resource provider)
          (mcp-oauth--resource-uri provider resource))
    provider))

(defun mcp-oauth--ensure-directory (directory)
  "Create DIRECTORY with private permissions when needed."
  (unless (file-directory-p directory)
    (make-directory directory t))
  (set-file-modes directory #o700))

(defun mcp-oauth--state-file-safe-p (file)
  "Return non-nil when FILE passes portable OAuth state safety checks.
Native Windows does not expose meaningful POSIX mode bits, so retain the
regular-file and symlink checks there without rejecting its synthetic modes."
  (and (not (file-symlink-p file))
       (file-regular-p file)
       (or (eq system-type 'windows-nt)
           (let ((modes (file-modes file)))
             (and modes (= 0 (logand #o077 modes)))))))

(defun mcp-oauth--load-state (provider)
  "Load and validate persisted OAuth state for PROVIDER."
  (let* ((file (mcp-oauth--state-file provider))
         (directory (file-name-directory file)))
    (mcp-oauth--ensure-directory directory)
    (when (file-exists-p file)
      (unless (mcp-oauth--state-file-safe-p file)
        (error "OAuth state file is unsafe"))
      (let ((state (with-temp-buffer
                     (insert-file-contents file)
                     (mcp-oauth--json (buffer-string) "OAuth state"))))
        (unless (equal (plist-get state :resource)
                       (mcp-oauth-provider-resource provider))
          (error "OAuth state resource does not match this MCP server"))
        (setf (mcp-oauth-provider-state provider) state)
        state))))

(defun mcp-oauth--save-state (provider state)
  "Atomically persist PROVIDER STATE with private permissions."
  (let* ((file (mcp-oauth--state-file provider))
         (directory (file-name-directory file)))
    (mcp-oauth--ensure-directory directory)
    (let ((temporary
           (make-temp-file (expand-file-name ".mcp-oauth-" directory))))
      (unwind-protect
          (progn
            (with-temp-file temporary
              (insert (json-serialize state :false-object :json-false)))
            (set-file-modes temporary #o600)
            (rename-file temporary file t)
            (set-file-modes file #o600)
            (setf (mcp-oauth-provider-state provider) state))
        (when (file-exists-p temporary) (delete-file temporary))))))

(defun mcp-oauth--delete-state (provider)
  "Delete persisted credentials for PROVIDER."
  (let ((file (mcp-oauth--state-file provider)))
    (when (file-exists-p file) (delete-file file)))
  (setf (mcp-oauth-provider-state provider) nil))

(defun mcp-oauth--headers (headers name)
  "Return all case-insensitive NAME values from raw HTTP HEADERS."
  (let ((needle (downcase name)) values)
    (dolist (line (split-string headers "[\r\n]+" t))
      (when-let* ((colon (string-match ":" line))
                  (field (downcase (string-trim (substring line 0 colon))))
                  ((string= field needle)))
        (push (string-trim (substring line (1+ colon))) values)))
    (nreverse values)))

(defun mcp-oauth--header (headers name)
  "Return the first case-insensitive NAME from raw HTTP HEADERS."
  (car (mcp-oauth--headers headers name)))

(defun mcp-oauth--bearer-resource-metadata (headers)
  "Return a quoted Bearer resource_metadata URL from HEADERS, or nil."
  (cl-loop for value in (mcp-oauth--headers headers "WWW-Authenticate")
           thereis
           (let ((case-fold-search t))
             (when (string-match "\\(?:\\`\\|,[[:space:]]*\\)Bearer[[:space:]]+" value)
               (let ((challenge (substring value (match-end 0))))
                 (when (string-match "resource_metadata[[:space:]]*=[[:space:]]*\\\"\\([^\\\"]+\\)\\\"" challenge)
                   (match-string 1 challenge)))))))

(defun mcp-oauth--metadata-url (provider)
  "Return RFC 9728 protected-resource metadata URL for PROVIDER."
  (or (mcp-oauth--config provider :metadata-url)
      (let* ((resource (url-generic-parse-url
                        (mcp-oauth-provider-resource provider)))
             (path (car (split-string (or (url-filename resource) "/") "?"))))
        (format "%s://%s%s/.well-known/oauth-protected-resource%s"
                (url-type resource)
                (url-host resource)
                (let* ((scheme (url-type resource))
                       (port (url-port resource)))
                  (if (or (null port)
                          (and (string= scheme "https") (= port 443))
                          (and (string= scheme "http") (= port 80)))
                      ""
                    (format ":%d" port)))
                (if (string= path "/") "" path)))))

(defconst mcp-oauth--metadata-probe-body
  "{\"jsonrpc\":\"2.0\",\"id\":0,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-03-26\",\"capabilities\":{},\"clientInfo\":{\"name\":\"Emacs MCP\",\"version\":\"0\"}}}"
  "Minimal unauthenticated MCP request used only for OAuth challenges.")

(defun mcp-oauth--valid-resource-metadata-p (provider metadata)
  "Return non-nil when METADATA identifies PROVIDER and an authorization server."
  (and (listp metadata)
       (stringp (plist-get metadata :resource))
       (let ((servers (plist-get metadata :authorization_servers)))
         (and (sequencep servers) (> (length servers) 0)))
       (condition-case nil
           (equal (mcp-oauth--resource-uri provider (plist-get metadata :resource))
                  (mcp-oauth-provider-resource provider))
         (error nil))))

(defun mcp-oauth--challenge-metadata-url (provider)
  "Probe PROVIDER resource once and return its 401 Bearer metadata URL."
  (pcase-let ((`(,status ,headers ,_body)
               (mcp-oauth--http provider "POST" (mcp-oauth-provider-resource provider)
                                '(("Content-Type" . "application/json")
                                  ("Accept" . "application/json, text/event-stream"))
                                mcp-oauth--metadata-probe-body)))
    (unless (= status 401)
      (error "OAuth protected resource metadata discovery failed: no Bearer challenge"))
    (let ((url (mcp-oauth--bearer-resource-metadata headers)))
      (unless url
        (error "OAuth protected resource metadata discovery failed: invalid Bearer challenge"))
      (mcp-oauth--require-url provider url "Bearer resource_metadata")
      url)))

(defun mcp-oauth--protected-resource-metadata (provider)
  "Fetch verified RFC 9728 metadata for PROVIDER, using one 401 challenge fallback."
  (let ((configured (mcp-oauth--config provider :metadata-url)))
    (if configured
        (let ((metadata (mcp-oauth--request-json provider "GET" configured nil nil
                                                  "protected resource metadata")))
          (unless (mcp-oauth--valid-resource-metadata-p provider metadata)
            (error "OAuth protected resource metadata is invalid"))
          metadata)
      (let ((derived (mcp-oauth--metadata-url provider)))
        (condition-case nil
            (let ((metadata (mcp-oauth--request-json provider "GET" derived nil nil
                                                     "protected resource metadata")))
              (if (mcp-oauth--valid-resource-metadata-p provider metadata)
                  metadata
                (error "invalid metadata")))
          (error
           (let ((metadata (mcp-oauth--request-json provider "GET"
                                                     (mcp-oauth--challenge-metadata-url provider)
                                                     nil nil "protected resource metadata")))
             (unless (mcp-oauth--valid-resource-metadata-p provider metadata)
               (error "OAuth protected resource metadata is invalid"))
             metadata)))))))

(defun mcp-oauth--authorization-server-metadata-url (provider issuer)
  "Return RFC 8414 metadata URL for PROVIDER authorization ISSUER."
  (mcp-oauth--require-url provider issuer "Authorization server")
  (let* ((parsed (url-generic-parse-url issuer))
         (port (url-port parsed))
         (path (or (url-filename parsed) "")))
    (when (string-match-p "[?#]" path)
      (error "Authorization server issuer must not contain query or fragment"))
    (format "%s://%s%s/.well-known/oauth-authorization-server%s"
            (url-type parsed) (url-host parsed)
            (if (and port (not (= port 443))) (format ":%d" port) "")
            (if (string-empty-p path) "" (concat "/" (string-remove-prefix "/" path))))))

(defun mcp-oauth--public-client-p (client)
  "Return non-nil when CLIENT uses no token endpoint authentication."
  (member (plist-get client :token_endpoint_auth_method) '(nil "none")))

(defun mcp-oauth--validate-public-client (client label)
  "Reject non-public CLIENT credentials at LABEL."
  (unless (mcp-oauth--public-client-p client)
    (error "%s must use token_endpoint_auth_method none" label))
  client)

(defun mcp-oauth-discover (provider)
  "Discover protected-resource and authorization-server metadata for PROVIDER."
  (let* ((resource-metadata (mcp-oauth--protected-resource-metadata provider))
         (configured-issuer (mcp-oauth--config provider :authorization-server))
         (declared-issuers (plist-get resource-metadata :authorization_servers))
         (issuer (or configured-issuer (seq-first declared-issuers))))
    (when (and configured-issuer declared-issuers
               (not (seq-contains-p declared-issuers configured-issuer #'equal)))
      (error "Configured authorization server is not declared by the resource"))
    (mcp-oauth--require-url provider issuer "Authorization server")
    (let* ((metadata-url (mcp-oauth--authorization-server-metadata-url provider issuer))
           (server-metadata
            (mcp-oauth--request-json provider "GET" metadata-url nil nil
                                     "authorization server metadata"))
           (declared-issuer (plist-get server-metadata :issuer)))
      (when (and declared-issuer (not (equal declared-issuer issuer)))
        (error "Authorization server metadata issuer does not match discovery"))
      (mcp-oauth--require-url provider (plist-get server-metadata :token_endpoint)
                              "token_endpoint")
      (when-let* ((declared-resource (plist-get resource-metadata :resource)))
        (unless (equal (mcp-oauth--resource-uri provider declared-resource)
                       (mcp-oauth-provider-resource provider))
          (error "Protected resource metadata does not match this MCP server")))
      (setf (mcp-oauth-provider-authorization-server provider) issuer
            (mcp-oauth-provider-metadata provider) server-metadata)
      (when-let* ((state (or (mcp-oauth-provider-state provider)
                             (mcp-oauth--load-state provider))))
        (unless (equal (plist-get state :issuer) issuer)
          (mcp-oauth--delete-state provider)
          (error "OAuth state issuer does not match discovered issuer")))
      server-metadata)))

(defun mcp-oauth--client (provider)
  "Return PROVIDER's registered or static client information."
  (or (mcp-oauth-provider-client provider)
      (let* ((state (or (mcp-oauth-provider-state provider)
                        (mcp-oauth--load-state provider)))
             (client (or (mcp-oauth--config provider :static-client)
                         (plist-get state :client))))
        (when client
          (mcp-oauth--validate-public-client client "OAuth client"))
        (setf (mcp-oauth-provider-client provider) client)
        client)))

(defun mcp-oauth--public-client-state (client)
  "Return the reusable public registration fields from CLIENT."
  (list :client_id (plist-get client :client_id)
        :token_endpoint_auth_method "none"))

(defun mcp-oauth--register (provider)
  "Dynamically register PROVIDER and persist its client information."
  (let* ((metadata (or (mcp-oauth-provider-metadata provider)
                       (mcp-oauth-discover provider)))
         (endpoint (plist-get metadata :registration_endpoint)))
    (mcp-oauth--require-url provider endpoint "Dynamic registration endpoint")
    (let ((client (mcp-oauth--request-json
                   provider "POST" endpoint
                   '(("Content-Type" . "application/json"))
                   (json-serialize
                    `(:client_name ,(or (mcp-oauth--config provider :client-name)
                                        "Emacs MCP client")
                      :grant_types ["urn:ietf:params:oauth:grant-type:device_code"
                                    "refresh_token"]
                      :token_endpoint_auth_method "none")
                    :false-object :json-false)
                   "dynamic registration")))
      (mcp-oauth--validate-public-client client "Dynamic registration response")
      (setq client (mcp-oauth--public-client-state client))
      (setf (mcp-oauth-provider-client provider) client)
      (mcp-oauth--save-state
       provider (list :resource (mcp-oauth-provider-resource provider)
                      :issuer (mcp-oauth-provider-authorization-server provider)
                      :client client))
      client)))

(defun mcp-oauth--ensure-client (provider)
  "Return a static, stored, or dynamically registered client for PROVIDER."
  (or (mcp-oauth--client provider)
      (mcp-oauth--register provider)))

(defun mcp-oauth--merge-state (provider tokens)
  "Merge TOKENS into PROVIDER state and persist them."
  (let* ((old (or (mcp-oauth-provider-state provider)
                  (mcp-oauth--load-state provider)
                  nil))
         (expires-in (plist-get tokens :expires_in))
         (state (append (list :resource (mcp-oauth-provider-resource provider)
                              :issuer (mcp-oauth-provider-authorization-server provider)
                              :client (mcp-oauth--ensure-client provider))
                        tokens
                        (when expires-in
                          (list :expires_at (+ (float-time) expires-in)))
                        (when (and old (not (plist-get tokens :refresh_token)))
                          (list :refresh_token (plist-get old :refresh_token))))))
    (mcp-oauth--save-state provider state)
    state))

(defun mcp-oauth--token-response (provider fields label)
  "POST OAuth FIELDS and return parsed token response for LABEL."
  (let* ((metadata (or (mcp-oauth-provider-metadata provider)
                       (mcp-oauth-discover provider)))
         (client (mcp-oauth--ensure-client provider))
         (form (mcp-oauth--form
                (append fields
                        (list (cons "client_id" (plist-get client :client_id))
                              (cons "resource"
                                    (mcp-oauth-provider-resource provider)))))))
    (pcase-let ((`(,status ,_headers ,body)
                 (mcp-oauth--http
                  provider "POST" (plist-get metadata :token_endpoint)
                  '(("Content-Type" . "application/x-www-form-urlencoded"))
                  form)))
      (cons status (mcp-oauth--json body label)))))

(defun mcp-oauth--token-request (provider fields label)
  "POST OAuth FIELDS to PROVIDER token endpoint for LABEL."
  (pcase-let ((`(,status . ,payload)
               (mcp-oauth--token-response provider fields label)))
    (unless (<= 200 status 299)
      (error "OAuth %s failed (%d): %s" label status
             (mcp-oauth--redact
              (or (plist-get payload :error)
                  (plist-get payload :error_description)
                  "request failed"))))
    (unless (stringp (plist-get payload :access_token))
      (error "OAuth %s did not return an access token" label))
    (mcp-oauth--merge-state provider payload)))

;;;###autoload
(defun mcp-oauth-token (provider)
  "Return PROVIDER's cached access token, or nil."
  (plist-get (or (mcp-oauth-provider-state provider)
                 (mcp-oauth--load-state provider)) :access_token))

(defun mcp-oauth--expired-p (provider)
  "Return non-nil when PROVIDER's access token needs renewal."
  (let ((state (or (mcp-oauth-provider-state provider)
                   (mcp-oauth--load-state provider))))
    (or (not (stringp (plist-get state :access_token)))
        (let ((expiry (plist-get state :expires_at)))
          (and expiry (<= expiry (+ (float-time) mcp-oauth-expiry-skew)))))))

;;;###autoload
(defun mcp-oauth-refresh (provider)
  "Refresh PROVIDER credentials, clearing stale state on invalid_grant."
  (condition-case err
      (let ((refresh-token (plist-get (or (mcp-oauth-provider-state provider)
                                          (mcp-oauth--load-state provider))
                                      :refresh_token)))
        (unless (stringp refresh-token) (error "No OAuth refresh token"))
        (mcp-oauth--token-request
         provider (list (cons "grant_type" "refresh_token")
                        (cons "refresh_token" refresh-token)) "refresh"))
    (error
     (when (string-match-p "invalid_grant" (error-message-string err))
       (mcp-oauth--delete-state provider))
     (signal (car err) (cdr err)))))

(defun mcp-oauth--open-browser (provider url)
  "Open PROVIDER authorization URL when configured to do so."
  (let ((opener (mcp-oauth--config provider :open-browser)))
    (when opener
      (if (functionp opener)
          (funcall opener url)
        (browse-url url)))))

(defun mcp-oauth--finish (provider state error)
  "Complete PROVIDER authorization waiters with STATE or safe ERROR."
  (when-let* ((timer (mcp-oauth-provider-poll-timer provider)))
    (cancel-timer timer))
  (setf (mcp-oauth-provider-poll-timer provider) nil)
  (let ((waiters (nreverse (mcp-oauth-provider-waiters provider))))
    (setf (mcp-oauth-provider-waiters provider) nil)
    (dolist (waiter waiters)
      (if state
          (funcall (car waiter) state)
        (funcall (cdr waiter) error)))))

(defun mcp-oauth--device-expired-p (device)
  "Return non-nil when DEVICE's absolute authorization deadline passed."
  (<= (plist-get device :expires_at) (float-time)))

(defun mcp-oauth--schedule-poll (provider device)
  "Schedule PROVIDER's next DEVICE poll, unless its deadline has passed."
  (if (mcp-oauth--device-expired-p device)
      (mcp-oauth--finish provider nil "OAuth device authorization expired")
    (setf (mcp-oauth-provider-poll-timer provider)
          (run-at-time (plist-get device :interval) nil
                       #'mcp-oauth--device-poll provider device))))

(defun mcp-oauth--device-poll (provider device)
  "Poll PROVIDER device authorization DEVICE once."
  (if (mcp-oauth--device-expired-p device)
      (mcp-oauth--finish provider nil "OAuth device authorization expired")
    (condition-case err
        (pcase-let* ((`(,status . ,payload)
                      (mcp-oauth--token-response
                       provider
                       (list (cons "grant_type" "urn:ietf:params:oauth:grant-type:device_code")
                             (cons "device_code" (plist-get device :device_code)))
                       "device authorization"))
                     (code (plist-get payload :error)))
          (cond
           ((<= 200 status 299)
            (mcp-oauth--finish provider (mcp-oauth--merge-state provider payload) nil))
           ((member code '("authorization_pending" "slow_down"))
            (when (equal code "slow_down")
              (plist-put device :interval (+ 5 (plist-get device :interval))))
            (mcp-oauth--schedule-poll provider device))
           ((member code '("invalid_grant" "expired_token" "access_denied"))
            (mcp-oauth--delete-state provider)
            (mcp-oauth--finish provider nil "OAuth device authorization expired, was denied, or was revoked"))
           (t (mcp-oauth--finish provider nil "OAuth device authorization failed"))))
      (error (mcp-oauth--finish provider nil
                                (mcp-oauth--redact (error-message-string err)))))))

;;;###autoload
(defun mcp-oauth-authorize (provider success failure)
  "Start OAuth device authorization for PROVIDER asynchronously.
Call SUCCESS with persisted token state after approval, or FAILURE with a
safe user-facing message.  PKCE loopback authorization is not implemented."
  (if (mcp-oauth-provider-waiters provider)
      (push (cons success failure) (mcp-oauth-provider-waiters provider))
    (setf (mcp-oauth-provider-waiters provider) (list (cons success failure)))
    (condition-case err
        (let* ((metadata (or (mcp-oauth-provider-metadata provider)
                             (mcp-oauth-discover provider)))
               (endpoint (plist-get metadata :device_authorization_endpoint))
               (client (mcp-oauth--ensure-client provider)))
          (mcp-oauth--require-url provider endpoint "Device authorization endpoint")
          (let* ((device (mcp-oauth--request-json
                          provider "POST" endpoint
                          '(("Content-Type" . "application/x-www-form-urlencoded"))
                          (mcp-oauth--form
                           (list (cons "client_id" (plist-get client :client_id))
                                 (cons "scope" (string-join (or (mcp-oauth--config provider :scopes) nil) " "))
                                 (cons "resource" (mcp-oauth-provider-resource provider))))
                          "device authorization"))
                 (verification-url (or (plist-get device :verification_uri_complete)
                                       (plist-get device :verification_uri)))
                 (expires-in (plist-get device :expires_in))
                 (interval (max 1 (or (plist-get device :interval) 5))))
            (unless (and (stringp (plist-get device :device_code))
                         (stringp verification-url) (stringp (plist-get device :user_code))
                         (numberp expires-in) (> expires-in 0))
              (error "Device authorization response is incomplete"))
            (mcp-oauth--require-url provider verification-url "Device verification URL")
            (plist-put device :interval interval)
            (plist-put device :expires_at (+ (float-time) expires-in))
            (mcp-oauth--open-browser provider verification-url)
            (message "Authorize MCP in your browser at %s; enter code %s"
                     verification-url (plist-get device :user_code))
            (mcp-oauth--schedule-poll provider device)))
      (error (mcp-oauth--finish provider nil
                                (mcp-oauth--redact (error-message-string err)))))))

;;;###autoload
(defun mcp-oauth-ensure-token (provider success failure)
  "Asynchronously ensure PROVIDER has a valid token.
Call SUCCESS with an access token or FAILURE with a safe diagnostic."
  (condition-case err
      (progn
        ;; Discover before trusting state, so a token cannot be reused after
        ;; authorization-server metadata for the resource has changed.
        (mcp-oauth-discover provider)
        (if (not (mcp-oauth--expired-p provider))
            (funcall success (mcp-oauth-token provider))
          (condition-case refresh-error
              (let ((state (mcp-oauth-refresh provider)))
                (funcall success (plist-get state :access_token)))
            (error
             (if (string-match-p "No OAuth refresh token\\|invalid_grant"
                                 (error-message-string refresh-error))
                 (mcp-oauth-authorize
                  provider
                  (lambda (state)
                    (funcall success (plist-get state :access_token)))
                  failure)
               (funcall failure
                        (mcp-oauth--redact
                         (error-message-string refresh-error))))))))
    (error
     (funcall failure (mcp-oauth--redact (error-message-string err))))))

;;;###autoload
(defun mcp-oauth-invalidate-access-token (provider)
  "Discard only PROVIDER's access token, retaining refresh credentials.
The next `mcp-oauth-ensure-token' first attempts a refresh, then begins device
authorization only if no usable refresh credential remains."
  (let ((state (or (mcp-oauth-provider-state provider)
                   (mcp-oauth--load-state provider))))
    (when state
      (setq state (plist-put state :access_token nil))
      (setq state (plist-put state :expires_at 0))
      (mcp-oauth--save-state provider state))))

;;;###autoload
(defun mcp-oauth-cancel-authorization (provider)
  "Cancel PROVIDER's in-flight device authorization without deleting credentials."
  (when (mcp-oauth-provider-waiters provider)
    (mcp-oauth--finish provider nil "OAuth device authorization cancelled")))

(declare-function mcp--oauth "mcp")
(defvar mcp-server-connections)

(defun mcp-oauth--read-provider ()
  "Read an active MCP server name and return its OAuth provider."
  (require 'mcp)
  (let (names)
    (maphash (lambda (name _connection) (push name names))
             mcp-server-connections)
    (unless names
      (user-error "No MCP server connections are available"))
    (let* ((name (completing-read "MCP server: " (sort names #'string<) nil t))
           (connection (gethash name mcp-server-connections))
           (provider (and connection (mcp--oauth connection))))
      (or provider
          (user-error "MCP server %s has no OAuth provider" name)))))

;;;###autoload
(defun mcp-oauth-clear-credentials (provider)
  "Clear persisted OAuth credentials for PROVIDER."
  (interactive (list (mcp-oauth--read-provider)))
  (mcp-oauth-cancel-authorization provider)
  (mcp-oauth--delete-state provider))

(provide 'mcp-oauth)
;;; mcp-oauth.el ends here
