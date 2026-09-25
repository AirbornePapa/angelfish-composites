// POST /.netlify/functions/qbo-test   JSON: { "password": "...", "amount": 1.00 (optional, per grade) }
// Admin-only SANDBOX smoke test: creates/reuses a test customer and a 2-grade invoice,
// then returns { customerId, invoiceId, docNumber, total, paymentLink }.
import { createCustomer, createInvoice, errorResponse, getAccessToken, getInvoicePaymentLink, json, passwordFromRequest, requireAdmin, QboError } from "./lib/qbo.mjs";

const TEST_QUOTE = {
  firstName: "Sandbox",
  lastName: "Tester",
  schoolName: "Sandbox Test School",
  displayName: "Sandbox Test School",
  email: "sandbox-test@angelfishhomes.com",
  phone: "(555) 555-0100",
  street: "100 Test Street",
  city: "Testville",
  state: "CA",
  zip: "90000",
};
const TEST_GRADES = ["3rd Grade", "4th Grade"];

export default async (req) => {
  try {
    if (req.method !== "POST") return json(405, { ok: false, error: "method_not_allowed" }, { Allow: "POST" });
    let body = {};
    try { body = await req.json(); } catch { body = {}; }
    requireAdmin(passwordFromRequest(req, body));
    const amount = body.amount !== undefined ? Number(body.amount) : 1;
    if (!Number.isFinite(amount) || amount < 0 || amount > 100) {
      throw new QboError(400, "invalid_amount", "amount must be a number between 0 and 100 for the sandbox test.");
    }
    await getAccessToken(); // clean not_configured / not_connected errors before doing anything
    const { customer, reused, matchedBy } = await createCustomer(TEST_QUOTE);
    const invoice = await createInvoice(customer.Id, TEST_GRADES, {
      unitPrice: amount,
      billEmail: TEST_QUOTE.email,
      schoolName: TEST_QUOTE.schoolName,
      memo: "Sandbox test invoice — not a real order.",
    });
    const pay = await getInvoicePaymentLink(invoice.Id);
    return json(200, {
      ok: true,
      environment: "sandbox",
      customerId: customer.Id,
      customerReused: reused,
      ...(matchedBy ? { customerMatchedBy: matchedBy } : {}),
      invoiceId: invoice.Id,
      docNumber: invoice.DocNumber || null,
      total: invoice.TotalAmt,
      paymentLink: pay.link || null,
      paymentLinkMessage: pay.message,
    });
  } catch (err) {
    return errorResponse(err);
  }
};
