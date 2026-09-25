# Didit Go Client

A drop-in Go client for [Didit](https://didit.me) identity verification. Ask a user to prove who they are, then gate access to a secret, an account, or a transaction behind that proof.

This package is a single file. It uses only the Go standard library. There is no SDK to install, no dependency to vendor, no version to pin. Copy `didit.go` into your project and call it a day.

---

## Before you start

You need three things from the Didit Console:

1. **An API key** — Settings → API & Webhooks.
2. **A workflow UUID** — Workflows → your KYC workflow. This is the "recipe" Didit follows: which documents to accept, whether to do liveness, whether to run AML, etc. You design it once in the Console; the client just references it.
3. **A webhook secret** — Settings → Webhooks. Every result notification is HMAC-signed with this secret.

Set them as environment variables:

```bash
export DIDIT_API_KEY="..."
export DIDIT_WORKFLOW_ID="550e8400-e29b-41d4-a716-446655440000"
export DIDIT_WEBHOOK_SECRET="..."
```

Then, once at startup:

```go
import "github.com/Louis-de-Lavenne-de-Choulot/didit_api_v3"

client, err := didit_api_v3.Init(didit_api_v3.Config{
    APIKey:        os.Getenv("DIDIT_API_KEY"),
    WorkflowID:    os.Getenv("DIDIT_WORKFLOW_ID"),
    WebhookSecret: os.Getenv("DIDIT_WEBHOOK_SECRET"),
})
if err != nil {
    log.Fatal(err)
}
```

Store the resulting `*Client` wherever your handlers can reach it. It is safe to use from many goroutines at once, so one client for the whole process is fine.

The rest of this document is organized around **what you are trying to do**.

---

## Use case 1 — Send someone a verification link

**The situation.** You want a specific person to prove their identity. They are not sitting next to you; they might be in another country. You will email them a link, they open it on their phone, scan their ID, take a selfie, and Didit tells you what happened.

**The call.**

```go
resp, err := client.CreateSession(ctx, didit_api_v3.CreateSessionRequest{
    VendorData: "client-42",                    // your internal ID for this person
    Callback:   "https://yourapp.com/thank-you", // where to send them when they finish
    Language:   "fr",                            // optional: force French UI
})
if err != nil {
    return err
}

// resp.URL is the link to email.
fmt.Println(resp.URL)
// → https://verify.didit.me/session/xyz...   (or your custom domain)
```

**What just happened.** Didit created a *session* — one attempt by one person to prove their identity. The session has an ID, a status (initially `"Not Started"` or `"In Progress"`), and a URL. Until someone opens that URL, the session just sits there.

**The `VendorData` field is important.** This is your own identifier for the person. It travels with the session and comes back to you in every webhook. Use your database's user ID, an email, or a case number. You will need it to match the result to the right human.

**The `Callback` field is where the browser goes after.** When the user finishes the verification flow in their browser, Didit redirects them to this URL. It is a *redirect*, not a notification — do not confuse it with the webhook. Send them to a "thank you, we'll be in touch" page.

**Shortcut for the common case:**

```go
link, err := client.CreateLink(ctx, "client-42", "https://yourapp.com/thank-you")
```

Same thing, but only the URL comes back.

---

## Use case 2 — Find out when someone passes

**The situation.** The user has opened the link, scanned their documents, and is done. You need to know: did they pass?

There are two ways to learn this. Use both.

### The webhook (preferred)

Register a URL in the Didit Console under Webhooks. Every time a session changes state — approved, declined, sent to review — Didit POSTs to that URL. Your handler looks like this:

```go
func HandleDiditWebhook(w http.ResponseWriter, r *http.Request) {
    event, err := client.VerifyWebhook(r)
    if err != nil {
        // Signature is wrong, timestamp is stale, or body is malformed.
        // Never trust this request.
        http.Error(w, "invalid", http.StatusUnauthorized)
        return
    }

    switch event.Status {
    case "Approved":
        // The person is verified. Release the secret, grant access, etc.
        grantAccess(event.VendorData)

    case "Declined":
        // Verification failed. Do not release anything.
        log.Printf("declined: %s", event.VendorData)

    case "In Review":
        // A human needs to look at this. Wait for a follow-up webhook.
        markForReview(event.VendorData)
    }

    // Always reply 2xx quickly. Didit retries on failure.
    w.WriteHeader(http.StatusOK)
}
```

**Why `VerifyWebhook` and not just `json.Unmarshal`?** Because a webhook is an untrusted HTTP request. Anyone on the internet can POST to your endpoint and claim that "client-42" passed. The only way to know a webhook is genuine is the HMAC signature, and `VerifyWebhook` is the function that checks it. It reads the raw body first (before you parse it), computes the HMAC, and compares. If you `json.Unmarshal` yourself first, you have already lost — the parsing changed the bytes, and the signature can never match.

**Idempotency.** Didit may retry a webhook. Use `event.EventID` as a deduplication key in your own database so you do not grant access twice.

### The polling fallback

Webhooks sometimes fail. Your server was restarting, your firewall dropped the request, whatever. Do not lose the result. Store the `SessionID` when you create the session, and poll if needed:

```go
decision, err := client.GetDecision(ctx, sessionID)
if err != nil {
    return err
}
if decision.Status == "Approved" {
    // Same as the webhook path.
}
```

This is also useful as a belt-and-braces check: when a webhook arrives claiming `"Approved"`, you can call `GetDecision` once more to confirm before doing anything irreversible.

---

## Use case 3 — Check that it is really the right person

**The situation.** You entered John Doe's expected details into your system. You sent the link to `john@example.com`. Someone completed the verification. But did *John Doe* complete it, or someone who guessed the email address?

The webhook gives you the name extracted from the ID document. You compare it to what you expected.

**Store the expected name when you create the session:**

```go
resp, err := client.CreateSession(ctx, didit_api_v3.CreateSessionRequest{
    VendorData: "client-42",
    Callback:   "https://yourapp.com/thank-you",
    Metadata: map[string]any{
        "expected_first_name": "John",
        "expected_last_name":  "Doe",
    },
})
```

`Metadata` is arbitrary JSON that Didit stores with the session and echoes back in every webhook. It is the cleanest way to carry your expectation to the comparison point.

**Compare in the webhook handler:**

```go
event, err := client.VerifyWebhook(r)
if err != nil { return }

if event.Status != "Approved" {
    // Nothing to compare against yet.
    return
}

// Extract the name the person actually presented on their document.
first, last, full, dob, ok := event.Decision.ExtractName()
if !ok {
    log.Printf("approved session %s but no approved ID document", event.SessionID)
    return
}

// What did we expect?
expFirst, _ := event.Metadata["expected_first_name"].(string)
expLast, _ := event.Metadata["expected_last_name"].(string)

if !namesMatch(first, last, expFirst, expLast) {
    log.Printf("name mismatch: got %q %q, expected %q %q", first, last, expFirst, expLast)
    // Do NOT release the secret. Flag for human review.
    return
}

// Name matches. The document, the face, and the name all agree.
releaseSecret(event.VendorData)
```

**Writing a reasonable `namesMatch`:**

```go
func namesMatch(gotFirst, gotLast, wantFirst, wantLast string) bool {
    norm := func(s string) string {
        s = strings.ToLower(strings.TrimSpace(s))
        s = strings.ReplaceAll(s, "-", " ")
        s = strings.ReplaceAll(s, "'", "")
        return s
    }
    return norm(gotFirst) == norm(wantFirst) && norm(gotLast) == norm(wantLast)
}
```

Case, whitespace, hyphens, and apostrophes are noise from OCR. Strip them all before comparing.

**About the caveat.** The name comparison is a *sanity check*, not the security boundary. The security guarantee comes from three things happening together:

1. The document passed Didit's authenticity checks.
2. The selfie is a live human, not a photo of a photo.
3. The selfie matches the photo on the document.

The name check catches the case where a *different, real* person completed the flow using their own valid ID. If you skip the name check, someone with a valid document can complete a session that was meant for someone else.

**If you want to be stricter**, the decision payload carries more than just the name. `PrimaryIDVerification()` returns the whole `IDVerification` struct — date of birth, issuing country, document number, expiry date. You can compare any or all of them:

```go
id := event.Decision.PrimaryIDVerification()
if id == nil { return }

if id.DateOfBirth != expectedDOB {
    // Wrong person.
}
if id.IssuingState != "FRA" {
    // Wrong document type.
}
if id.DocumentLiveness["printed_copy"].Bucket != "approve" {
    // Suspected printout fraud.
}
```

---

## Use case 4 — Approve or decline a session manually

**The situation.** A session came back `"In Review"` because the document quality was marginal or the face match was borderline. You looked at it yourself, and you want to make a call.

```go
resp, err := client.UpdateSessionStatus(ctx, sessionID, didit_api_v3.UpdateStatusRequest{
    NewStatus: "Approved",
    Comment:   "Manual review by ops@yourapp.com — document was legible on closer inspection.",
})
```

**The other direction:**

```go
_, err := client.UpdateSessionStatus(ctx, sessionID, didit_api_v3.UpdateStatusRequest{
    NewStatus: "Declined",
    Comment:   "Selfie does not match the document portrait.",
})
```

**Asking the user to try again.** If a single feature failed — say, the document photo was too blurry but everything else passed — you can re-open just that step instead of making the user start over:

```go
_, err := client.UpdateSessionStatus(ctx, sessionID, didit_api_v3.UpdateStatusRequest{
    NewStatus: "Resubmitted",
    NodesToResubmit: []didit_api_v3.ResubmitNode{
        {NodeID: "ocr-node-id", Feature: "OCR"},
    },
    SendEmail:     true,
    EmailAddress:  "john@example.com",
    EmailLanguage: "en",
})
```

Didit emails the user a link to redo just the document scan. Everything else they already did is preserved.

**Where do I get the NodeID?** From the decision payload. Each `IDVerification`, `LivenessCheck`, etc. carries a `NodeID` field.

---

## Use case 5 — Download a compliance PDF

**The situation.** Your regulator, your lawyer, or your file archive wants a printable proof of the verification.

```go
pdf, err := client.GenerateSessionPDF(ctx, sessionID)
if err != nil {
    return err
}
os.WriteFile("verification-42.pdf", pdf, 0o600)
```

**If you want every session for one person bundled into a single PDF:**

```go
pdf, err := client.GenerateUserHistoryPDF(ctx, "client-42")
os.WriteFile("client-42-history.pdf", pdf, 0o600)
```

The user-history PDF includes every reportable session keyed by the same `VendorData` — useful for KYC audits where you need to show the full relationship, not just one moment in time.

---

## Use case 6 — Manage the humans you verify

**The situation.** You have verified the same person several times over the years. You want to see their history, block them if something goes wrong, or flag them for closer attention in the future.

**List everyone you have ever verified:**

```go
page, err := client.ListUsers(ctx, didit_api_v3.ListUsersParams{
    Status:   "ACTIVE",       // or "FLAGGED", "BLOCKED"
    Search:   "john",         // substring match on name or vendor_data
    PageSize: 50,
})
for _, u := range page.Results {
    fmt.Printf("%s: %s — %d sessions, %d approved\n",
        u.VendorData, u.FullName, u.SessionCount, u.ApprovedCount)
}
```

**Look up one person:**

```go
u, err := client.GetUser(ctx, "client-42")
fmt.Println(u.FullName, u.Status, u.SessionCount)
```

**Flag them for future attention.** A flagged user's new sessions can be routed to manual review by your workflow's policy:

```go
_, err := client.UpdateUserStatus(ctx, "client-42", "FLAGGED")
```

**Block them entirely.** A blocked user cannot pass a new session:

```go
_, err := client.UpdateUserStatus(ctx, "client-42", "BLOCKED")
```

**Delete a user.** Prefer `BLOCKED` for everyday use — deletion is irreversible and cascades.

```go
_, err := client.BatchDeleteUsers(ctx, didit_api_v3.BatchDeleteUsersRequest{
    VendorDataList: []string{"client-42", "client-43"},
})

// Or wipe every user for your application (dangerous):
_, err := client.BatchDeleteUsers(ctx, didit_api_v3.BatchDeleteUsersRequest{
    DeleteAll: true,
})
```

---

## Use case 7 — Block or allow known entities

**The situation.** You have noticed a specific face, document number, or email showing up in fraudulent sessions. You want Didit to automatically flag any future session that matches.

Didit organizes these rules into *lists*. There are two types you manage yourself:

- **Allowlists** — only entities on this list can pass. Everyone else is flagged.
- **Custom lists** — informational; you check them in your own logic.

There are also **system blocklists**, which Didit pre-populates. You can add to them, but the entries they already contain are managed by Didit.

**See what lists exist:**

```go
lists, err := client.ListLists(ctx, didit_api_v3.ListListsParams{})
for _, l := range lists.Results {
    fmt.Printf("%s (%s, %d entries)\n", l.Name, l.ListType, l.EntryCount)
}
```

**Add a face to a blocklist** so it is flagged in every future session:

```go
entry, err := client.AddEntry(ctx, blocklistUUID, didit_api_v3.AddEntryRequest{
    Value:        "biometric-template-uuid-here",
    DisplayLabel: "Fraudulent actor from case #42",
    Comment:      "Confirmed printout attack — 2024-11-15",
})
```

**Or reference the session directly** and let Didit extract the face for you:

```go
entry, err := client.AddEntry(ctx, blocklistUUID, didit_api_v3.AddEntryRequest{
    ReferenceSessionID: sessionID,
    Comment:            "Auto-blocked after confirmed fraud",
})
```

**Remove an entry** (on a system blocklist, this unblocks the entity):

```go
err := client.DeleteEntry(ctx, blocklistUUID, entryUUID)
```

**Create your own allowlist** for a private beta:

```go
list, err := client.CreateList(ctx, didit_api_v3.CreateListRequest{
    Name:        "Q4 private beta",
    Description: "Invited users only",
    ListType:    "allowlist",
    EntryType:   "email",
})
```

---

## Use case 8 — Share a verified session with a partner

**The situation.** You verified Alice. Now a partner service — say a bank — also needs to trust Alice, but you do not want to make her verify again.

Didit lets you mint a short-lived token that the partner redeems on their own Didit application. They get a copy of the verification result; Alice gets to keep her sanity.

```go
// On your side:
share, err := client.ShareSession(ctx, sessionID, didit_api_v3.ShareSessionRequest{
    ForApplicationID: "partner-app-uuid",
    TTLInSeconds:     3600, // valid for one hour
})
// Send share.ShareToken to the partner out-of-band.

// On the partner's side:
imported, err := partnerClient.ImportSharedSession(ctx, didit_api_v3.ImportSharedSessionRequest{
    ShareToken: tokenFromYou,
})
fmt.Println(imported.SessionID, imported.Status)
```

The token is a signed JWT bound to a specific partner application and a specific session. It cannot be reused by a third party. Set the TTL as short as your use case allows.

---

## Use case 9 — Clean up data (GDPR)

**The situation.** A user has asked you to delete everything, or your retention policy says session data older than X must be erased.

```go
resp, err := client.DeleteSession(ctx, sessionID, &didit_api_v3.DeleteSessionRequest{
    DeletionInstruction: "privacy_erasure",
    InstructionID:       "gdpr-request-42", // your own audit reference
})
```

**About face retention.** By default, deletion uses the application's face-retention policy from the Didit Console. You can override it per-deletion:

```go
retain := false
resp, err := client.DeleteSession(ctx, sessionID, &didit_api_v3.DeleteSessionRequest{
    RetainFaceEmbeddings: &retain,  // force-delete the face template too
    DeletionInstruction:  "privacy_erasure",
})
```

Or to retain the face template for future cross-matching (e.g. to block this person from re-registering):

```go
retain := true
resp, err := client.DeleteSession(ctx, sessionID, &didit_api_v3.DeleteSessionRequest{
    RetainFaceEmbeddings:  &retain,
    FaceRetentionDays:     90,
    DeletionInstruction:   "operational_session_delete",
})
```

**Pass `nil` for the third argument** if you just want the default behaviour:

```go
client.DeleteSession(ctx, sessionID, nil)
```

---

## Use case 10 — Browse past sessions

**The situation.** You want a list of every session you have run, filtered by status or date, for reporting or customer support.

```go
page, err := client.ListSessions(ctx, didit_api_v3.ListSessionsParams{
    Status:     "Approved,In Review",     // comma-separated
    DateFrom:   "2024-01-01",
    DateTo:     "2024-12-31",
    VendorData: "client-42",              // optional filter
    Limit:      100,
})

for _, s := range page.Results {
    fmt.Printf("%s — %s — %s\n", s.SessionID, s.VendorData, s.Status)
}

// Follow page.Next to get the next page.
```

**Pagination.** The response carries `Next` and `Previous` URLs. Pass them straight back to Didit if you want — they are complete, signed URLs.

---

## Use case 11 — Manage workflows programmatically

**The situation.** You deploy to many environments and want to script workflow creation instead of clicking through the Console. Or you need to A/B test different workflows.

Most teams never touch this section. The Console is fine. But if you do need it:

```go
list, err := client.ListWorkflows(ctx, 50, 0)
for _, wf := range list.Results {
    fmt.Printf("%s: %s (%s)\n", wf.UUID, wf.WorkflowLabel, wf.WorkflowType)
}

wf, err := client.GetWorkflow(ctx, workflowUUID)

// Create a minimal KYC workflow.
newWF, err := client.CreateWorkflow(ctx, didit_api_v3.CreateWorkflowRequest{
    WorkflowLabel: "EU KYC — strict",
    WorkflowType:  "kyc",
    Features: []didit_api_v3.WorkflowFeature{
        {Feature: "OCR", Config: map[string]any{
            "allowed_documents": []string{"passport", "identity_card"},
            "allowed_countries": []string{"FRA", "DEU", "ESP"},
        }},
        {Feature: "LIVENESS", Config: map[string]any{
            "method": "ACTIVE_3D",
        }},
        {Feature: "FACE_MATCH"},
        {Feature: "AML", Config: map[string]any{
            "datasets": []string{"EU_SANCTIONS", "OFAC"},
        }},
    },
})

// Patch it later.
_, err = client.UpdateWorkflow(ctx, newWF.UUID, didit_api_v3.CreateWorkflowRequest{
    WorkflowLabel: "EU KYC — strict v2",
})

// Delete when done.
err = client.DeleteWorkflow(ctx, newWF.UUID)
```

**Do not delete a workflow that sessions still reference.** Existing sessions keep working from their stored snapshot, but new sessions cannot use a deleted workflow.

---

## Error handling

Every method returns an `error`. When the error is an API-level failure (a 4xx or 5xx from Didit), the concrete type is `*didit_api_v3.APIError`:

```go
resp, err := client.CreateSession(ctx, req)
if err != nil {
    var apiErr *didit_api_v3.APIError
    if errors.As(err, &apiErr) {
        switch apiErr.StatusCode {
        case 401, 403:
            log.Printf("auth problem: %s", apiErr.Body)
        case 404:
            log.Printf("not found: %s", apiErr.Body)
        case 429:
            // Rate limited. Back off and retry.
        default:
            log.Printf("didit error %d: %s", apiErr.StatusCode, apiErr.Body)
        }
        return err
    }
    // Network error, context cancellation, or JSON decode failure.
    return err
}
```

`apiErr.Body` contains Didit's raw response — usually a JSON object with a `detail` field explaining what went wrong. Surface it in your logs; it is written for developers.

**Webhook verification errors are different.** They are always plain `error` values — the point is that *something* is wrong and you should reject the request. Common causes:

- `missing X-Timestamp header` — Didit is not the caller.
- `webhook timestamp too old` — a replay attack, or your clock is wrong.
- `webhook signature mismatch` — the webhook secret is wrong, or the body was tampered with.
- `decode webhook` — the payload shape is not what the library expects, likely a Didit API version bump.

Log the error, return 401, and move on.

---

## Concurrency and lifecycle

The `*Client` is safe to use from any number of goroutines. Initialize it once in `main` and share it. Do not create a new client per request; each `Init` allocates an HTTP client with its own connection pool.

If you need to change the timeout or the underlying `http.Client` (e.g. to inject a proxy or custom transport), pass it in:

```go
client, _ := didit_api_v3.Init(didit_api_v3.Config{
    APIKey:     apiKey,
    WorkflowID: workflowID,
    WebhookSecret: secret,
    HTTPClient: &http.Client{
        Timeout: 60 * time.Second,
        Transport: customTransport,
    },
})
```

If you need to reach a mock server in tests, override `BaseURL`:

```go
didit_api_v3.Init(didit_api_v3.Config{
    // ...
    BaseURL: "http://localhost:8080/v3",
})
```

---

## Complete example: the secret-sharing flow

Putting it all together — this is the flow that started this project.

**Step 1.** When the user opens the sharing request, create a Didit session with the name you expect them to present.

```go
resp, err := client.CreateSession(ctx, didit_api_v3.CreateSessionRequest{
    VendorData: clientEmail,
    Callback:   "https://yourapp.com/verified",
    Metadata: map[string]any{
        "expected_first_name": "John",
        "expected_last_name":  "Doe",
        "secret_id":           secretID, // tie this to the secret you will send
    },
})
if err != nil { return err }

// Email resp.URL to clientEmail.
```

**Step 2.** The user clicks the link, does the verification, and Didit POSTs back.

```go
func HandleDiditWebhook(w http.ResponseWriter, r *http.Request) {
    event, err := client.VerifyWebhook(r)
    if err != nil {
        http.Error(w, "invalid", http.StatusUnauthorized)
        return
    }

    if event.Status != "Approved" {
        w.WriteHeader(http.StatusOK)
        return
    }

    first, last, _, _, ok := event.Decision.ExtractName()
    if !ok {
        w.WriteHeader(http.StatusOK)
        return
    }

    expFirst, _ := event.Metadata["expected_first_name"].(string)
    expLast, _ := event.Metadata["expected_last_name"].(string)
    secretID, _ := event.Metadata["secret_id"].(string)

    if !namesMatch(first, last, expFirst, expLast) {
        log.Printf("name mismatch for %s", event.VendorData)
        w.WriteHeader(http.StatusOK)
        return
    }

    // Identity verified. Now generate the one-time link for the secret.
    if err := emailOneTimeSecretLink(event.VendorData, secretID); err != nil {
        log.Printf("could not send secret: %v", err)
    }

    w.WriteHeader(http.StatusOK)
}
```

**Step 3.** The user receives a second email — the one-time link. They click it, and the secret is revealed once, then gone forever. They were only able to receive it because they proved their identity in step 2.

The attacker who has compromised the user's mailbox sees both emails, but cannot pass the identity check. The one-time link is useless on its own because the secret is only generated *after* the identity check passes.

---

## What the library does not do

A short list of things this package deliberately does not handle, so you know where the boundaries are:

- **Sending emails.** It returns a URL; you send it.
- **Storing verification results.** The webhook tells you what happened; you decide what to persist.
- **Deciding who gets access.** That is application logic.
- **Verifying that an ID document is legitimate.** Didit does that; the library just relays the answer.

If something feels missing, it is probably yours to build.

---

## Where to look in the code

Every public function has a doc comment. Start there — `go doc github.com/Louis-de-Lavenne-de-Choulot/didit_api_v3` will list them all. The struct fields on `Decision` and its nested types mirror the Didit V3 API exactly, so if the Console shows a field, it is in there under a camel-cased Go name.