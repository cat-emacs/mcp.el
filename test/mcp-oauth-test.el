;;; mcp-oauth-test.el --- Tests for mcp-oauth -*- lexical-binding: t; -*-
(require 'ert)
(require 'cl-lib)
(require 'mcp-oauth)

(defmacro mcp-oauth-test-with-provider (&rest body)
  `(let* ((directory (make-temp-file "mcp-oauth-test-" t))
          (provider (mcp-oauth-create "https://mcp.example.test/v1?tenant=a"
                                      (list :storage-directory directory :open-browser nil))))
     (unwind-protect (progn ,@body) (delete-directory directory t))))

(ert-deftest mcp-oauth-test-resource-keeps-query-and-rejects-fragment ()
  (should (equal (mcp-oauth-provider-resource (mcp-oauth-create "https://mcp.example.test/v1?tenant=a"))
                 "https://mcp.example.test/v1?tenant=a"))
  (should-not (equal (mcp-oauth--state-file (mcp-oauth-create "https://mcp.example.test/v1?a"))
                     (mcp-oauth--state-file (mcp-oauth-create "https://mcp.example.test/v1?b"))))
  (should-error (mcp-oauth-create "https://mcp.example.test/v1#fragment")))

(ert-deftest mcp-oauth-test-rfc8414-root-and-path-issuer-urls ()
  (let ((provider (mcp-oauth-create "https://mcp.example.test/v1")))
    (should (equal (mcp-oauth--authorization-server-metadata-url provider "https://issuer.test")
                   "https://issuer.test/.well-known/oauth-authorization-server"))
    (should (equal (mcp-oauth--authorization-server-metadata-url provider "https://issuer.test/tenant")
                   "https://issuer.test/.well-known/oauth-authorization-server/tenant"))
    (should-error (mcp-oauth--authorization-server-metadata-url provider "https://issuer.test/a?x=1"))))

(ert-deftest mcp-oauth-test-redacts-common-text-forms ()
  (let ((text (mcp-oauth--redact
               "{\"access_token\":\"a\", refresh_token: r, 'client_secret'=s, device_code=d, code=c} Authorization: Bearer bearer")))
    (let ((case-fold-search nil))
      (dolist (secret '("\"a\"" "refresh_token: r" "=s" "=d" "=c" "bearer"))
        (should-not (string-match-p (regexp-quote secret) text))))
    (should (string-match-p "REDACTED" text))))

(ert-deftest mcp-oauth-test-refuses-redirect-without-parsing-body ()
  (mcp-oauth-test-with-provider
   (cl-letf (((symbol-function 'mcp-oauth--http)
              (lambda (&rest _) '(302 "Location: http://evil.test" "access_token=secret"))))
     (let ((message (condition-case err
                        (mcp-oauth--request-json provider "GET" "https://issuer.test/x" nil nil "metadata")
                      (error (error-message-string err)))))
       (should (string-match-p "redirect refused" message))
       (should-not (string-match-p "secret" message))))))

(ert-deftest mcp-oauth-test-state-round-trips-json-arrays ()
  (mcp-oauth-test-with-provider
   (let* ((client (mcp-oauth--json
                   "{\"client_id\":\"client\",\"grant_types\":[\"device_code\",\"refresh_token\"]}"
                   "test client"))
          (state (list :resource (mcp-oauth-provider-resource provider)
                       :issuer "https://issuer.test"
                       :client client)))
     (mcp-oauth--save-state provider state)
     (setf (mcp-oauth-provider-state provider) nil)
     (let ((loaded (mcp-oauth--load-state provider)))
       (should (equal ["device_code" "refresh_token"]
                      (plist-get (plist-get loaded :client) :grant_types)))))))

(ert-deftest mcp-oauth-test-combined-auth-bearer-bypasses-basic-handler ()
  (mcp-oauth-test-with-provider
   (let (delegated)
     (cl-letf (((symbol-function 'url-retrieve-synchronously)
                (lambda (&rest _)
                  (with-temp-buffer
                    (insert "HTTP/1.1 401 Unauthorized\r\n"
                            "WWW-Authenticate: Basic realm=\"x\", Bearer resource_metadata=\"https://issuer.test/metadata\"\r\n\r\n")
                    (setq-local url-http-end-of-headers (point-max))
                    (should (funcall (symbol-function
                                      'url-http-handle-authentication)
                                     nil)))
                  nil))
               ((symbol-function 'url-http-handle-authentication)
                (lambda (_proxy) (setq delegated t))))
       (should-error
        (mcp-oauth--http provider "POST"
                         "https://mcp.example.test/v1" nil "{}"))
       (should-not delegated)))))

(ert-deftest mcp-oauth-test-derived-metadata-url-excludes-query ()
  (mcp-oauth-test-with-provider
   (should (equal
            "https://mcp.example.test/.well-known/oauth-protected-resource/v1"
            (mcp-oauth--metadata-url provider)))))

(ert-deftest mcp-oauth-test-bearer-401-bypasses-basic-auth-handler ()
  (mcp-oauth-test-with-provider
   (let (delegated)
     (cl-letf (((symbol-function 'url-retrieve-synchronously)
                (lambda (&rest _)
                  (with-temp-buffer
                    (insert "HTTP/1.1 401 Unauthorized\n"
                            "WWW-Authenticate: Bearer resource_metadata=\"https://issuer.test/metadata\"\n\n")
                    (setq-local url-http-end-of-headers (point-max))
                    (should (funcall (symbol-function
                                      'url-http-handle-authentication)
                                     nil)))
                  nil))
               ((symbol-function 'url-http-handle-authentication)
                (lambda (_proxy) (setq delegated t))))
       (should-error
        (mcp-oauth--http provider "POST"
                         "https://mcp.example.test/v1" nil "{}"))
       (should-not delegated)))))

(ert-deftest mcp-oauth-test-disables-url-redirects ()
  (mcp-oauth-test-with-provider
   (let (redirects)
     (cl-letf (((symbol-function 'url-retrieve-synchronously)
                (lambda (&rest _) (setq redirects url-max-redirections) nil)))
       (should-error (mcp-oauth--http provider "GET" "https://issuer.test/x" nil nil))
       (should (= redirects 0))))))

(ert-deftest mcp-oauth-test-requires-token-endpoint-not-authorization-endpoint ()
  (mcp-oauth-test-with-provider
   (cl-letf (((symbol-function 'mcp-oauth--http)
              (lambda (_p _m url _h _d)
                (if (string-match-p "protected-resource" url)
                    '(200 "" "{\"resource\":\"https://mcp.example.test/v1?tenant=a\",\"authorization_servers\":[\"https://issuer.test\"]}")
                  '(200 "" "{\"issuer\":\"https://issuer.test\",\"token_endpoint\":\"https://issuer.test/token\"}")))))
     (should (plist-get (mcp-oauth-discover provider) :token_endpoint)))))

(ert-deftest mcp-oauth-test-public-client-state-drops-unused-secret ()
  (should (equal '(:client_id "client" :token_endpoint_auth_method "none")
                 (mcp-oauth--public-client-state
                  '(:client_id "client"
                    :client_secret "unused"
                    :token_endpoint_auth_method "none")))))

(ert-deftest mcp-oauth-test-rejects-non-public-clients ()
  (should-error (mcp-oauth--validate-public-client '(:client_id "x" :token_endpoint_auth_method "client_secret_post") "test")))

(ert-deftest mcp-oauth-test-load-rejects-unsafe-state ()
  (mcp-oauth-test-with-provider
   (mcp-oauth--save-state
    provider `(:resource ,(mcp-oauth-provider-resource provider)
                         :issuer "https://issuer.test"))
   (let ((file (mcp-oauth--state-file provider)))
     ;; Exercise POSIX mode policy independently of the host filesystem.
     (cl-letf (((symbol-function 'file-modes) (lambda (_) #o644))
               ((symbol-function 'file-symlink-p) (lambda (_) nil))
               ((symbol-function 'file-regular-p) (lambda (_) t)))
       (let ((system-type 'gnu/linux))
         (should-error (mcp-oauth--load-state provider))))
     ;; Symlinks remain unsafe on every platform, including native Windows.
     (cl-letf (((symbol-function 'file-symlink-p) (lambda (_) "target"))
               ((symbol-function 'file-regular-p) (lambda (_) t)))
       (should-error (mcp-oauth--load-state provider)))
     (cl-letf (((symbol-function 'file-modes) (lambda (_) #o666))
               ((symbol-function 'file-symlink-p) (lambda (_) nil))
               ((symbol-function 'file-regular-p) (lambda (_) t)))
       (let ((system-type 'windows-nt))
         (should (mcp-oauth--state-file-safe-p file))))
     (let ((system-type 'windows-nt))
       (cl-letf (((symbol-function 'file-symlink-p) (lambda (_) "target"))
                 ((symbol-function 'file-regular-p) (lambda (_) t)))
         (should-not (mcp-oauth--state-file-safe-p file)))
       (cl-letf (((symbol-function 'file-symlink-p) (lambda (_) nil))
                 ((symbol-function 'file-regular-p) (lambda (_) nil)))
         (should-not (mcp-oauth--state-file-safe-p file)))))))

(ert-deftest mcp-oauth-test-single-flight-and-cancel ()
  (mcp-oauth-test-with-provider
   (let ((calls 0) (failures 0) timer)
     (setf (mcp-oauth-provider-metadata provider) '(:device_authorization_endpoint "https://issuer.test/device")
           (mcp-oauth-provider-client provider) '(:client_id "client"))
     (cl-letf (((symbol-function 'mcp-oauth--request-json)
                (lambda (&rest _) (setq calls (1+ calls))
                  '(:device_code "hidden" :verification_uri "https://issuer.test/v" :user_code "u" :expires_in 60)))
               ((symbol-function 'run-at-time) (lambda (&rest _) (setq timer 'timer) timer))
               ((symbol-function 'cancel-timer) (lambda (_timer) (setq timer 'cancelled))))
       (mcp-oauth-authorize provider #'ignore (lambda (_) (setq failures (1+ failures))))
       (mcp-oauth-authorize provider #'ignore (lambda (_) (setq failures (1+ failures))))
       (should (= calls 1)) (mcp-oauth-cancel-authorization provider)
       (should (eq timer 'cancelled)) (should (= failures 2))))))

(ert-deftest mcp-oauth-test-expired-device-never-polls-or-reschedules ()
  (mcp-oauth-test-with-provider
   (let ((requests 0) (scheduled 0) failed)
     (setf (mcp-oauth-provider-waiters provider) (list (cons #'ignore (lambda (e) (setq failed e)))))
     (cl-letf (((symbol-function 'mcp-oauth--token-response) (lambda (&rest _) (setq requests (1+ requests))))
               ((symbol-function 'run-at-time) (lambda (&rest _) (setq scheduled (1+ scheduled)))))
       (mcp-oauth--device-poll provider '(:expires_at 0 :interval 1 :device_code "x"))
       (mcp-oauth--schedule-poll provider '(:expires_at 0 :interval 1))
       (should (= requests 0)) (should (= scheduled 0)) (should failed)))))

(defun mcp-oauth-test--metadata ()
  "Return valid protected-resource metadata for the standard fixture."
  "{\"resource\":\"https://mcp.example.test/v1?tenant=a\",\"authorization_servers\":[\"https://issuer.test\"]}")

(ert-deftest mcp-oauth-test-derived-protected-metadata-skips-probe ()
  (mcp-oauth-test-with-provider
   (let (calls)
     (cl-letf (((symbol-function 'mcp-oauth--http)
                (lambda (_provider method url headers data)
                  (push (list method url headers data) calls) (list 200 "" (mcp-oauth-test--metadata)))))
       (should (mcp-oauth--protected-resource-metadata provider))
       (should (equal (mapcar #'car calls) '("GET")))))))

(ert-deftest mcp-oauth-test-challenge-discovers-protected-metadata ()
  (mcp-oauth-test-with-provider
   (let (calls)
     (cl-letf (((symbol-function 'mcp-oauth--http)
                (lambda (_provider method url headers data)
                  (push (list method url headers data) calls)
                  (cond ((and (equal method "GET") (string-match-p "oauth-protected-resource/v1" url)) '(404 "" "not json"))
                        ((equal method "POST") '(401 "wWw-AuThEnTiCaTe: Basic realm=\"x\", Bearer scope=\"mcp\", resource_metadata=\"https://metadata.example.test/resource\"" "ignored"))
                        ((equal url "https://metadata.example.test/resource") (list 200 "" (mcp-oauth-test--metadata)))
                        (t (error "unexpected request"))))))
       (should (mcp-oauth--protected-resource-metadata provider))
       (let ((ordered (nreverse calls)))
         (should (equal (mapcar #'car ordered) '("GET" "POST" "GET")))
         (should (equal (nth 1 (cadr ordered)) "https://mcp.example.test/v1?tenant=a"))
         (should (string-match-p "\\\"method\\\":\\\"initialize\\\"" (nth 3 (cadr ordered))))
         (should-not (assoc "Authorization" (nth 2 (cadr ordered)))))))))

(ert-deftest mcp-oauth-test-challenge-rejects-invalid-metadata-urls ()
  (mcp-oauth-test-with-provider
   (dolist (headers '("WWW-Authenticate: Bearer scope=\"x\""
                      "WWW-Authenticate: Bearer resource_metadata=\"http://insecure.test/meta\""))
     (cl-letf (((symbol-function 'mcp-oauth--http)
                (lambda (_provider method _url _headers _data) (if (equal method "POST") (list 401 headers "") '(404 "" "")))))
       (should-error (mcp-oauth--protected-resource-metadata provider))))))

(ert-deftest mcp-oauth-test-only-401-bearer-challenge-is-accepted ()
  (mcp-oauth-test-with-provider
   (cl-letf (((symbol-function 'mcp-oauth--http)
              (lambda (_provider method _url _headers _data) (if (equal method "POST") '(403 "WWW-Authenticate: Bearer resource_metadata=\"https://metadata.test/x\"" "") '(404 "" "")))))
     (should-error (mcp-oauth--protected-resource-metadata provider)))))

(ert-deftest mcp-oauth-test-explicit-metadata-override-skips-probe ()
  (let* ((directory (make-temp-file "mcp-oauth-test-" t))
         (provider (mcp-oauth-create "https://mcp.example.test/v1" (list :storage-directory directory :metadata-url "https://override.test/meta"))) calls)
    (unwind-protect
        (cl-letf (((symbol-function 'mcp-oauth--http)
                   (lambda (_provider method url _headers _data) (push (list method url) calls)
                     '(200 "" "{\"resource\":\"https://mcp.example.test/v1\",\"authorization_servers\":[\"https://issuer.test\"]}"))))
          (should (mcp-oauth--protected-resource-metadata provider))
          (should (equal calls '(("GET" "https://override.test/meta")))))
      (delete-directory directory t))))

(provide 'mcp-oauth-test)
