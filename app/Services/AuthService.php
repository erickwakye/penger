<?php

namespace App\Services;

use App\Mail\OtpMail;
use App\Models\Otp;
use App\Models\User;
use Carbon\Carbon;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Str;


class AuthService {


    public function register(object $request) : User
    {
        $user = User::create([
            'uuid' => Str::uuid(),
            'name' => $request->name,
            'email' => $request->email,
            'password' => $request->password
        ]);

        //send the otp
        $this->otp($user);

        return $user;
    }

    public function login(object $request) : ?User
    {
        $user = User::where('email', $request->email)->first();

        if($user && Hash::check($request->password, $user->password)) {
            return $user;
        }

        return null;
    }

    public function otp(User $user, string $type = 'verification') : Otp{

        //check for spam and throttling
        $tries = 3;
        $time = Carbon::now()->subMinute(30);

        $count = Otp::where([
            'user_id' => $user->id,
            'type' => $type,
            'active' => 1
        ])->where('created_at', '>=', $time->count());

        if($count >= $tries) {
            abort(422, 'Too many OTP Request');
        }

        $code = random_int(100000, 999999);

        $otp = Otp::create([
            'user_id' => $user->id,
            'type' => $type,
            'code' => $code,
            'active' => 1
        ]);

        // send mail
        Mail::to($user)->send(new OtpMail($user, $otp));

        return $otp;
    }

    public function verify(User $user, object $request) : User{

        $otp = Otp::where([
            'user_id' => $user->id,
            'code' => $request->otp,
            'active' => 1,
            'type' => 'verification'
        ])->first();

        if(!$otp) {
            abort(422, __('app.invalid_otp'));
        }

        //if found update user
        $user->email_verified_at = Carbon::now();
        $user->update();

        $otp->active = 0;
        $otp->updated_at = Carbon::now();
        $otp->update();

        return $user;
    }


    public function getUserByEmail(string $email) : User
    {
        return $user = User::where('email', $email)->first();

    }

    public function resetPassword(User $user, object $request): User {

        $otp = Otp::where([
            'user_id' => $user->id,
            'code' => $request->otp,
            'type' => 'password-reset',
            'active' => 1
        ])->first();

        if(!$otp) {
            abort(422, __('app.invalid_otp'));
        }

        //if found update user
        $user->password = $request->password;
        $user->updated_at = Carbon::now();
        $user->update();

        $otp->active = 0;
        $otp->updated_at = Carbon::now();
        $otp->update();

        return $user;

    }
}
