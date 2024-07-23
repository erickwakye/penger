<x-mail::message>
<h4>Hi {{ $user->name}},</h4>

<p>Welcome to Penger.</p><br>

<p>Your verifcation code is <strong>{{' '.$otp->code}}</strong></p>

@if ($otp->type == 'password-reset')
Use this code to reset your password in the app.
@else
Use this code to complete the verification process in the app.
@endif

Thanks,<br>
{{ config('app.name') }}
</x-mail::message>
