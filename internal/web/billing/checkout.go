// internal/web/billing/checkout.go
package billing

import (
	"fmt"

	"github.com/stripe/stripe-go/v82"
	"github.com/stripe/stripe-go/v82/checkout/session"
	"github.com/stripe/stripe-go/v82/customer"
)

func CreateCheckoutSession(stripeSecretKey, priceID, successURL, cancelURL, customerEmail, existingCustomerID string) (checkoutURL, stripeCustomerID string, err error) {
	stripe.Key = stripeSecretKey

	stripeCustomerID = existingCustomerID
	if stripeCustomerID == "" {
		cust, err := customer.New(&stripe.CustomerParams{Email: stripe.String(customerEmail)})
		if err != nil {
			return "", "", fmt.Errorf("creating stripe customer: %w", err)
		}
		stripeCustomerID = cust.ID
	}

	params := &stripe.CheckoutSessionParams{
		Mode:       stripe.String(string(stripe.CheckoutSessionModeSubscription)),
		SuccessURL: stripe.String(successURL),
		CancelURL:  stripe.String(cancelURL),
		Customer:   stripe.String(stripeCustomerID),
		LineItems: []*stripe.CheckoutSessionLineItemParams{
			{
				Price:    stripe.String(priceID),
				Quantity: stripe.Int64(1),
			},
		},
	}

	sess, err := session.New(params)
	if err != nil {
		return "", "", fmt.Errorf("creating checkout session: %w", err)
	}
	return sess.URL, stripeCustomerID, nil
}
