# Vulnerable: ships an order before payment is confirmed. The scanner
# can't see this — it requires understanding business intent. This is the
# canonical AI-Discovery-catches-what-scanners-miss case.
# Classic logic flaw, no specific CWE; OWASP A04:2021 Insecure Design.

from flask import Flask, request

app = Flask(__name__)
ORDERS: dict[int, dict] = {}


@app.route("/checkout", methods=["POST"])
def checkout():
    order_id = int(request.json["order_id"])
    order = ORDERS[order_id]

    # Looks innocuous, but `payment_status == "pending"` includes the
    # case where the customer abandoned the payment flow. Shipping before
    # the gateway returns "captured" is the bug.
    if order["payment_status"] in ("pending", "captured"):
        ship_order(order_id)
        return {"shipped": True}
    return {"shipped": False}


def ship_order(order_id: int) -> None:
    # Pretend to call the fulfillment API.
    pass
