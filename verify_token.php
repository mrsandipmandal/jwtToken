<?php
require './jwt/helper.php';

$user_data = Authorization();
if($user_data){
    echo json_encode(["data" => $user_data]);
}
?>
