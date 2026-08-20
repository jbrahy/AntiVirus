package config

import (
	"fmt"
	"os"
)

type Config struct {
	DBDSN               string
	StripeSecretKey     string
	StripeWebhookSecret string
	StripePriceID       string
	CheckoutSuccessURL  string
	CheckoutCancelURL   string
	SessionSecret       string
	Port                string
}

func Load() (*Config, error) {
	c := &Config{
		DBDSN:               os.Getenv("DB_DSN"),
		StripeSecretKey:     os.Getenv("STRIPE_SECRET_KEY"),
		StripeWebhookSecret: os.Getenv("STRIPE_WEBHOOK_SECRET"),
		StripePriceID:       os.Getenv("STRIPE_PRICE_ID"),
		CheckoutSuccessURL:  os.Getenv("CHECKOUT_SUCCESS_URL"),
		CheckoutCancelURL:   os.Getenv("CHECKOUT_CANCEL_URL"),
		SessionSecret:       os.Getenv("SESSION_SECRET"),
		Port:                os.Getenv("PORT"),
	}
	if c.Port == "" {
		c.Port = "8100"
	}

	var missing []string
	if c.DBDSN == "" {
		missing = append(missing, "DB_DSN")
	}
	if c.StripeSecretKey == "" {
		missing = append(missing, "STRIPE_SECRET_KEY")
	}
	if c.StripeWebhookSecret == "" {
		missing = append(missing, "STRIPE_WEBHOOK_SECRET")
	}
	if c.StripePriceID == "" {
		missing = append(missing, "STRIPE_PRICE_ID")
	}
	if c.CheckoutSuccessURL == "" {
		missing = append(missing, "CHECKOUT_SUCCESS_URL")
	}
	if c.CheckoutCancelURL == "" {
		missing = append(missing, "CHECKOUT_CANCEL_URL")
	}
	if c.SessionSecret == "" {
		missing = append(missing, "SESSION_SECRET")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("missing required environment variables: %v", missing)
	}
	return c, nil
}
