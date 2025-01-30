<?php

namespace App\Gateways\PayByLink;

use LaraPay\Framework\Interfaces\GatewayFoundation;
use Illuminate\Support\Facades\Http;
use LaraPay\Framework\Payment;
use Illuminate\Http\Request;
use Exception;

class Gateway extends GatewayFoundation
{
    /**
     * Define the gateway identifier. This identifier should be unique. For example,
     * if the gateway name is "PayPal Express", the gateway identifier should be "paypal-express".
     *
     * @var string
     */
    protected string $identifier = 'paybylink';

    /**
     * Define the gateway version.
     *
     * @var string
     */
    protected string $version = '1.0.0';

    public function config(): array
    {
        return [
            'shop_id' => [
                'label' => 'Shop ID',
                'description' => 'Enter your shop ID',
                'type' => 'text',
                'rules' => ['required'],
            ],
            'secret_key' => [
                'label' => 'Secret Key',
                'description' => 'Enter your PayByLink secret key',
                'type' => 'text',
                'rules' => ['required'],
            ],
        ];
    }

    public function pay($payment)
    {
        // retrieve the gateway
        $gateway = $payment->gateway;

        // store a random key to later use for signature validation
        $webhookSecret = $this->generateWebhookSecret($gateway);

        // define variables
        $secretKey = $gateway->config('secret_key');
        $shopId = (int) $gateway->config('shop_id');
        $amount = (float) $payment->total();
        $notifyURL = $payment->webhookUrl();
        $returnUrlSuccess = $payment->successUrl();

        // Format the amount to 2 decimal places
        $amountFormatted = number_format($amount, 2, '.', '');

        // define the control
        $control = json_encode(['payment_id' => $payment->id, 'webhook_secret' => $webhookSecret]);

        // Concatenate the fields with the separator
        $concatenated = "{$secretKey}|{$shopId}|{$amountFormatted}|{$control}|{$payment->description}|{$notifyURL}|{$returnUrlSuccess}";

        // Generate the SHA256 hash of the concatenated string
        $signature = hash('sha256', $concatenated);

        // Send the request to the gateway
        $response = Http::post('https://secure.paybylink.pl/api/v1/transfer/generate', [
            'shopId' => $shopId,
            'price' => $amountFormatted, // Use the formatted amount
            'control' => $control,
            'description' => $payment->description,
            'notifyURL' => $notifyURL,
            'returnUrlSuccess' => $returnUrlSuccess,
            'signature' => $signature,
        ]);

    }

    public function callback(Request $request)
    {
        if(!$request->has('control')) {
            throw new Exception('Invalid request');
        }

        // decode the control
        $control = json_decode($request->control);

        // retrieve the payment
        $payment = Payment::where('id', $control->payment_id)->firstOrFail();

        if(!$payment) {
            throw new \Exception('Payment not found');
        }

        // validate the webhook key
        if($payment->gateway->config('webhook_secret') !== $control->webhook_secret) {
            throw new \Exception('Invalid webhook secret key');
        }

        // complete the payment
        $payment->completed($request->get('transactionId'));

        // return 200 response
        return response('OK', 200)->header('Content-Type', 'text/plain');
    }

    private function generateWebhookSecret($gateway)
    {
        if($gateway->config('webhook_secret')) {
            return $gateway->config('webhook_secret');
        }

        $secret = Str::random(32);

        $gateway->config = array_merge($gateway->config, [
            'webhook_secret' => $secret,
        ]);

        $gateway->save();

        return $secret;
    }
}
