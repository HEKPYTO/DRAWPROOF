use crate::bundle::VerifiedBundle;

pub fn html(verified: &VerifiedBundle) -> String {
    let mut out = String::new();
    out.push_str("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>DrawProof receipt</title><style>");
    out.push_str("body{font-family:system-ui,sans-serif;max-width:72rem;margin:2rem auto;padding:0 1rem;line-height:1.5;color:#111}");
    out.push_str("h1,h2{margin-top:2rem}table{border-collapse:collapse;width:100%;margin:1rem 0}th,td{border:1px solid #bbb;padding:.4rem .6rem;text-align:left;vertical-align:top}");
    out.push_str("code{overflow-wrap:anywhere}.ok{color:#0a6b2a}.muted{color:#555}");
    out.push_str("</style></head><body>");
    out.push_str("<h1>DrawProof receipt</h1>");
    if verified.policy_applied {
        out.push_str("<p class=\"ok\"><strong>Verified.</strong> The sample is the deterministic output of the pinned beacon round over the committed dataset, and the supplied signer policy was met.</p>");
    } else {
        out.push_str("<p class=\"ok\"><strong>Internally consistent.</strong> No signer policy was supplied; receipts may be self-signed and are not independent evidence.</p>");
    }
    out.push_str("<h2>Commitment</h2><table><tbody>");
    row(&mut out, "Dataset root", &verified.commitment.root);
    row(&mut out, "Item count", &verified.commitment.n.to_string());
    row(&mut out, "Sample size", &verified.commitment.k.to_string());
    row(
        &mut out,
        "Registration round",
        &verified.commitment.round.to_string(),
    );
    row(&mut out, "Nonce", &verified.commitment.nonce);
    row(&mut out, "Commitment SHA-256", &verified.commitment_sha256);
    let policy = if verified.policy_applied {
        format!(
            "{} of {} allowlisted signers",
            verified.required, verified.policy_signers
        )
    } else {
        "not supplied".to_string()
    };
    row(&mut out, "Signer policy", &policy);
    out.push_str("</tbody></table>");
    out.push_str("<h2>Public randomness</h2><table><tbody>");
    row(&mut out, "Network", &verified.chain);
    row(
        &mut out,
        "Selection round",
        &verified.beacon_round.to_string(),
    );
    row(&mut out, "Randomness", &verified.randomness);
    out.push_str("</tbody></table>");
    out.push_str("<h2>Receipts</h2><table><thead><tr><th>Server</th><th>Public key</th><th>Signed at round</th><th>Counted</th><th>Timely</th></tr></thead><tbody>");
    for item in &verified.receipts {
        let receipt = &item.receipt;
        out.push_str("<tr>");
        cell(&mut out, &receipt.server);
        cell(&mut out, &receipt.public_key);
        cell(&mut out, &receipt.signed_at_round.to_string());
        cell(&mut out, if item.counted { "yes" } else { "no" });
        cell(&mut out, if item.timely { "yes" } else { "no" });
        out.push_str("</tr>");
    }
    out.push_str("</tbody></table>");
    out.push_str(&format!(
        "<p>{} of {} required receipts were present and timely.</p>",
        verified.timely_receipts, verified.required
    ));
    out.push_str("<h2>Sample</h2><table><thead><tr><th>Index</th><th>Item id</th><th>Item hash</th></tr></thead><tbody>");
    for item in &verified.sample {
        out.push_str("<tr>");
        cell(&mut out, &item.index.to_string());
        cell(&mut out, &item.item_id);
        cell(&mut out, &item.item_hash);
        out.push_str("</tr>");
    }
    out.push_str("</tbody></table>");
    out.push_str("<h2>Assumptions</h2><ul>");
    out.push_str("<li>The drand quicknet threshold holds: fewer than the threshold of beacon nodes colluded.</li>");
    out.push_str("<li>At least one required receipt signer observed the commitment before the selection round and signed honestly.</li>");
    if verified.policy_applied {
        out.push_str("<li>The verifier was given the expected signer keys out of band, and the required threshold was met by allowlisted keys.</li>");
    } else {
        out.push_str("<li>No signer policy was supplied, so the bundle's own required count and public keys are self-declared.</li>");
    }
    out.push_str("<li>The committed dataset is the dataset the holder disclosed; DrawProof does not prove completeness or truthfulness.</li>");
    out.push_str("<li>SHA-256 is collision resistant and Ed25519 is unforgeable.</li>");
    out.push_str("</ul>");
    out.push_str("<h2>What this does not prove</h2><ul>");
    out.push_str("<li>That every item in the population is present in the committed dataset.</li>");
    out.push_str("<li>That no other commitment was registered or abandoned before this one; an offline bundle cannot show undisclosed commitments.</li>");
    out.push_str("<li>That the sample represents an uncommitted population.</li>");
    out.push_str(
        "<li>That the dataset contents are private; the commitment leaks size and membership.</li>",
    );
    out.push_str("<li>Anything about elections, lotteries, or legally binding draws.</li>");
    out.push_str("</ul>");
    out.push_str("<p class=\"muted\">Generated by DrawProof from a locally verified bundle. No network access is required to check this page.</p>");
    out.push_str("</body></html>");
    out
}

fn row(out: &mut String, label: &str, value: &str) {
    out.push_str("<tr><th>");
    out.push_str(&escape(label));
    out.push_str("</th><td><code>");
    out.push_str(&escape(value));
    out.push_str("</code></td></tr>");
}

fn cell(out: &mut String, value: &str) {
    out.push_str("<td><code>");
    out.push_str(&escape(value));
    out.push_str("</code></td>");
}

fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}
