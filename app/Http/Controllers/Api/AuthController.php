<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Http\Resources\UserResource;
use App\Services\AuthService;
use Illuminate\Http\Request;
use Illuminate\Http\Response;

class AuthController extends Controller
{
    protected AuthService $authService;

    public function __construct(AuthService $authService) {
        $this->authService = $authService;
    }


    public function register(Request $request): Response {

        // validate request
        $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|email|max:255|unique:users,email',
            'password' => 'required|min:6|max:255'
        ]);
        // create user
        $user = $this->authService->register($request);
        // create access tokens
        $token = $user->createToken('auth')->plainTextToken;
        // return the user
        return response([
            'message' => __('app.registration_success_verify'),
            'results' => [
                'user' => new UserResource($user),
                'token' => $token
            ]
        ], 201);
    }

    public function login(Request $request): Response {

        // validate request
        $request->validate([
            'email' => 'required|email|max:255',
            'password' => 'required|min:6|max:255'
        ]);
        // login user
        $user = $this->authService->login($request);

        if(!$user) {
            return response([
                'message' => __('auth.failed'),
            ], 401);
        }
        // create access tokens
        $token = $user->createToken('auth')->plainTextToken;
        // return the user
        return response([
            'message' => $user->email_verified_at ? __('app.login_success') : __('app.login_success_verify'),
            'results' => [
                'user' => new UserResource($user),
                'token' => $token
            ]
        ]);
    }

    public function otp(Request $request): Response {

        // login user
        $user = auth()->user();

        // generate otp
        $otp = $this->authService->otp($user);

        // return the user
        return response([
            'message' =>__('app.otp_sent_success'),
        ]);
    }

    public function verify(Request $request): Response {

        // validate the user
        $request->validate([
            'otp' => 'required|numeric',
        ]);

        // get user
        $user = auth()->user();

        // validate otp
        $user = $this->authService->verify($user, $request);

        // return the response
        return response([
            'message' =>__('app.verification_success'),
            'results' => [
                'user' => new UserResource($user)
            ]
        ]);
    }

    public function resetOtp(Request $request): Response {

        // validate the request
        $request->validate([
            'email' => 'required|email|max:255|exists:users,email'
        ]);

        // get user
        $user = $this->authService->getUserByEmail($request->email);

        // generate otp
        $otp = $this->authService->otp($user, 'password-reset');

        // return the user
        return response([
            'message' =>__('app.otp_sent_success'),
        ]);
    }

    public function resetPassword(Request $request): Response {

        // validate the otp
        $request->validate([
            'email' => 'required|email|max:255|exists:users,email',
            'otp' => 'required|numeric',
            'password' => 'required|min:6|max:255|confirmed',
            'password_confirmation' => 'required|min:6|max:255',
        ]);

        // get the user
        $user = $this->authService->getUserByEmail($request->email);

        // reset user pass otp
        $user = $this->authService->resetPassword($user, $request);

        // return the user
        return response([
            'message' =>__('app.password_reset_success'),
        ]);
    }
}
