<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
if($_SERVER['REQUEST_METHOD']!=='POST'){die(json_encode(['ok'=>false,'msg'=>'Bad method']));}

$name     = htmlspecialchars(trim($_POST['name']     ?? ''));
$email    = htmlspecialchars(trim($_POST['email']    ?? ''));
$phone    = htmlspecialchars(trim($_POST['phone']    ?? ''));
$dob      = htmlspecialchars(trim($_POST['dob']      ?? ''));
$address  = htmlspecialchars(trim($_POST['address']  ?? ''));
$ec       = htmlspecialchars(trim($_POST['emergency_contact'] ?? ''));
$access   = htmlspecialchars(trim($_POST['accessibility'] ?? ''));
$plan     = htmlspecialchars(trim($_POST['plan']     ?? ''));
$ts       = date('Y-m-d H:i:s');

if(!$name||!$email||!$dob||!$address){
    echo json_encode(['ok'=>false,'msg'=>'Missing required fields']); exit;
}
// Age check
$age = (int)((time()-strtotime($dob))/(365.25*86400));
if($age<16){echo json_encode(['ok'=>false,'msg'=>'Must be 16+']); exit;}

// Save registration to local CSV log
$log_file = __DIR__.'/registrations.csv';
$row = [$ts,$name,$email,$phone,$dob,$address,$ec,$access,$plan];
$fp = fopen($log_file,'a');
fputcsv($fp,$row); fclose($fp);

// Handle photo upload
$photo_saved = '';
if(!empty($_FILES['photo']['tmp_name'])){
    $upload_dir = __DIR__.'/uploads/';
    if(!is_dir($upload_dir)) mkdir($upload_dir,0755,true);
    $ext = pathinfo($_FILES['photo']['name'],PATHINFO_EXTENSION);
    $filename = 'reg_'.time().'_'.preg_replace('/[^a-z0-9]/i','',$name).'.'.$ext;
    if(move_uploaded_file($_FILES['photo']['tmp_name'],$upload_dir.$filename))
        $photo_saved = $filename;
}

// Email director
$to      = 'director@k-nexus.co.uk';
$subject = '=?UTF-8?B?'.base64_encode('NEW K-NEXUS REGISTRATION: '.$name.' — '.$plan).'?=';
$body    = "NEW MEMBER REGISTRATION\n\n"
         . "Name:          $name\n"
         . "Email:         $email\n"
         . "Phone:         $phone\n"
         . "Date of Birth: $dob (Age: $age)\n"
         . "Address:       $address\n"
         . "Emergency:     $ec\n"
         . "Accessibility: $access\n"
         . "Plan:          $plan\n"
         . "Photo:         ".($photo_saved?:"Not uploaded")."\n"
         . "Submitted:     $ts\n\n"
         . "Log on to RIFT to assign RFID card and activate account.\n"
         . "-- K-NEXUS RIFT Auto-Registration System";
$headers = "From: registration@k-nexus.co.uk\r\nReply-To: $email\r\nX-Mailer: K-NEXUS-RIFT";
mail($to,$subject,$body,$headers);

// Confirmation email to member
$conf_subject = '=?UTF-8?B?'.base64_encode('Welcome to K-NEXUS! Your registration is received').'?=';
$conf_body    = "Hi $name,\n\nThank you for registering with K-NEXUS Dundee CIC!\n\n"
              . "Your registration is confirmed and our team will review it within 2 working days.\n"
              . "When you first visit the hub, your RFID card will be ready at the front desk.\n\n"
              . "Membership Plan: $plan\n\n"
              . "If you have any questions, email us at director@k-nexus.co.uk\n\n"
              . "We can\'t wait to welcome you to K-NEXUS.\n\n"
              . "— K-NEXUS Dundee CIC\n  director@k-nexus.co.uk\n  CIC SC881084";
mail($email,$conf_subject,$conf_body,"From: K-NEXUS Dundee CIC <director@k-nexus.co.uk>");

echo json_encode(['ok'=>true,'msg'=>'Registration submitted successfully']);
?>