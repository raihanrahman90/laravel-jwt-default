<?php

namespace App\Classes;
use Illuminate\Http\Exceptions\HttpResponseException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;

class ApiResponseClass
{

    public static function rollback($e, $message = "Something went wrong!") {
        DB::rollBack();
        self::throw($e, $message);
    }

    public static function throw($e, $message="Something went wrong!") {
        Log::info($e);
        throw new HttpResponseException(response()->jsnon(["message"=>$message]));
    }

    public static function sendResponse($result, $message, $code=200) {
        $response = [
            'success'   => true,
            'data'      => $result
        ];

        if(!empty($message)){
            $response['message'] = $message;
        }
        return response()->json($response, $code);
    }
}
