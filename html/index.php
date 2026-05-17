<?php

define ( 'BASE_DIR', __DIR__ );
define ( 'SECRETS_DIR', BASE_DIR."/secrets/" );
define ( 'SECRET_SALT', "nnI4kvbzcT93IyrHVsuVat7PzO-lQ0NBOKgtat8AiYFRg7PstY0PJTuzy8owW8sdAgXOLokWA1RohW9twiupEIz-IL2U2zqffcHy7VWSHMg0ZwP77vkHbb_CnY1bo59d0" );
date_default_timezone_set ( 'UTC' );


//Modification à faire :
//On ne traite que les demandes dont l'URL ne contient pas de fichier
//ou dont le fichier est un html, htm ou php


//
//	Start PHP session
//
if (session_start ( )==false)
{
	echo "session error";
	die();
}
//$sServerKeyText = "nnI4kvbzcT93IyrHVsuVat7PzO-lQ0NBOKgtat8AiYFRg7PstY0PJTuzy8owW8sdAgXOLokWA1RohW9twiupEIz-IL2U2zqffcHy7VWSHMg0ZwP77vkHbb_CnY1bo59d0";





if ($_SERVER['REQUEST_METHOD'] === 'GET')
{
	if (isset($_GET['expire']))
	{
		//Site normal
		IndexMain ( $_GET['expire'] );	
	}
	else
	{	
		$sPath = trim(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH), '/');
		
		if ($sPath=='')
		{
			//Site normal
			IndexMain ( "" );
		}
		else if (preg_match('/^[A-Za-z0-9_-]{16,24}$/', $sPath))
		{
			//On affiche la page pour découvrir le secret
			if (IndexShowSecret ( $sPath )!=0)
				IndexMain ( "" );
		}
		else
		{
			//Erreur mais on redirige vers le site normal
			//Sauf si on vient de générer une session il y a moins de 2sec
			$bNoIndexMain = false;
			if (isset($_SESSION['ServerTime']))
			{
				$iCurrentTime 	= time();
				$iPreviousTime 	= intval($_SESSION['ServerTime']);
				if (($iCurrentTime-$iPreviousTime)<2)
					$bNoIndexMain = true;
			}
			if ($bNoIndexMain==false)
				IndexMain ( "" );
			
			//Modification à faire :
			//On ne traite que les demandes dont l'URL ne contient pas de fichier
			//ou dont le fichier est un html, htm ou php
		}
	}
}

if ($_SERVER['REQUEST_METHOD'] === 'POST')
{
	/*
		store = stocker un secret
		query = demande à lire un secret (et effacement si nécessaire)
	
	*/
	
	if (isset($_GET['store']))
	{
		if ($_COOKIE['ServerKey'] == $_SESSION['ServerKey'])
		{
			$sServerKey = $_SESSION['ServerKey'];
			if (strlen($sServerKey)==16)
			{
				$sMessage = file_get_contents('php://input');
				
				if (json_validate($sMessage)==true)
				{
					$oMessage = json_decode ( $sMessage, true );
				}
				else
				{
					$oMessage = null;
				}
				
				if ($oMessage!=null)
				{
					$sMessageServerKey = base64url_decode ( $oMessage['serverkey'] );
					
					if ($sMessageServerKey==$sServerKey)
					{
						//On nettoie le mot de passe d'effacement si on est pas en mode "ondemand"
						if ($oMessage['expire']!="ondemand")
							$oMessage['removepassword'] = "";
						
						if ($oMessage['expire']=="1read")
							$oMessage['secretpassword'] = "";
						
						SecretWrite ( $sServerKey, json_encode ( $oMessage ) );
						http_response_code(200);
						die();
					}
				}
			}
		}
		
		http_response_code(405);
		die();
	}
	
	if (isset($_GET['query']))
	{
		$sBase64ServerKey = file_get_contents('php://input');
		$sServerKey = base64url_decode($sBase64ServerKey);
		$sMessage = SecretRead ( $sServerKey );
		
		if (json_validate($sMessage)==true)
		{
			$oMessage = json_decode ( $sMessage, true );
		}
		else
		{
			$oMessage = null;
		}
		
		if ($oMessage!=null)
		{
			if ($oMessage['expire']=='1read')
			{
				unlink ( SecretGetFullPathName ( $sServerKey ) );
			}
		}
		
		
		echo $sMessage;
		http_response_code(200);
		die();
	}
}

die ( );




//########################################################
//
//	main page
//
//########################################################
function IndexMain ( $sExpire )
{
	/*
		Generate the base key and the secret file
	*/
	$sRandomKey = GenerateBaseKey ( SECRET_SALT );
	$sRandomKeyBase64 = base64url_encode ( $sRandomKey );
	
	
	$sIndexFile = file_get_contents ( "index.html" );
	$sIndexFile .= "<script>sRandomKeyBase64 = \"".$sRandomKeyBase64."\";\nsRandomKeyHexa = \"".bin2hex($sRandomKey)."\";</script>";

	if ($sExpire!="")
	{
		$sIndexFile .= "<style>#block-expire { display: none !important; }</style>";
		$sID = "";
		
		switch ($sExpire)
		{
			case "24h":
			case "7d":
			case "30d":
			case "ondemand":
			case "never":
				$sID = $sExpire;
				break;
			default:
				$sID = "1read";
				break;
		}
		$sIndexFile .= "<script>
			window.onpageshow = function(event) {
				$('#block-expire #btnradio-".$sID."').prop('checked',true);
			}</script>";
		//$('#block-expire #btnradio-'.$sID).prop('checked',true);
		//$("#block-expire input:checked:data").val();
		//$('#radioButtonName').prop('checked');
		//$("#block-expire input:checked").attr("expire")
	}

	echo $sIndexFile;
	
	session_destroy();
	session_start();
	$_SESSION = array();

	setcookie ( "ServerKey", $sRandomKey, time()+3600 );
	$_SESSION['ServerKey'] = $sRandomKey;
	$_SESSION['ServerTime'] = time();
	//session_id ( $sRandomKey );
	
}

//########################################################
//
//	show secret page
//
//########################################################
function IndexShowSecret ( $sPath )
{
	$sIndexFile = file_get_contents ( "index-secret.html" );
	
	//echo $sPath;
	
	try {
		$sServerKey = base64url_decode ( $sPath );
	} catch ( Exception $e ) {
		return -1;
	}
	
	//echo $sServerKey;
	$sMessage = SecretRead ( $sServerKey );
	
	
	if (json_validate($sMessage)==true)
	{
		$oMessage = json_decode ( $sMessage, true );
	}
	else
	{
		$oMessage = null;
	}
				
	if ($oMessage!=null)
	{
		$sMessageServerKey = base64url_decode ( $oMessage['serverkey'] );
		
		if ($sMessageServerKey==$sServerKey)
		{	
			$oMessage['iv'] = "";
			$oMessage['data'] = "";
			
			if (strlen($oMessage['secretpassword']))
				$oMessage['secretpassword'] = "yes";
			
			if (strlen($oMessage['removepassword']))
				$oMessage['removepassword'] = "yes";
			
			//echo json_encode ( $oMessage );
			
			$sScriptLoad = "";
			
			//Le secret en lecture unique
			switch ($oMessage['expire'])
			{
				case '1read':
					$sScriptLoad .= "$(\"#show-warningsecret-1read\").show();\n";
					break;
					
				case 'ondemand':
					$sScriptLoad .= "$(\"#show-warningsecret-ondemand\").show();\n";
					break;
					
				case 'never':
					$sScriptLoad .= "$(\"#show-warningsecret-never\").show();\n";
					break;
					
				default:
					$sScriptLoad .= "$(\"#show-warningsecret-time\").show();\n";
					break;
			}
			
			if ($oMessage['secretpassword']=="yes")
			{
				$sScriptLoad .= "$(\"#show-secretpassword\").show();\n";
			}
			
			
			
			$sIndexFile .= "<script>
			sServerKey = \"".$oMessage['serverkey']."\";
			sExpire = \"".$oMessage['expire']."\";
			sSecretPasswordEnabled = \"".$oMessage['secretpassword']."\";
			sRemovePasswordEnabled = \"".$oMessage['removepassword']."\";
			window.onpageshow = function(event) {
				".$sScriptLoad."
			}</script>";
			
			
			echo $sIndexFile;
			http_response_code(200);
			die();
		}
	}	
	
	return -1;
}

































function SecretGetFullPathName ( $sServerKey )
{
	$sHashedName = hash( 'sha256', SECRET_SALT.$sServerKey );
	return SECRETS_DIR.$sHashedName.".bin";
}

function SecretWrite ( $sServerKey, $sRawData )
{
	$sFileName = SecretGetFullPathName ( $sServerKey );
	if (file_exists($sFileName)==false)
	{	
		file_put_contents ( 
			$sFileName, 
			$sRawData );
	}
}

function SecretRead ( $sServerKey )
{
	return file_get_contents ( 
		SecretGetFullPathName ( $sServerKey ) );
}

function SecretExists ( $sServerKey )
{
	return file_exists ( 
		SecretGetFullPathName ( $sServerKey ) );
}




function base64url_encode( $data ){
  return rtrim( strtr( base64_encode( $data ), '+/', '-_'), '=');
}

function base64url_decode( $data ){
  return base64_decode( strtr( $data, '-_', '+/') . str_repeat('=', 3 - ( 3 + strlen( $data )) % 4 ));
}

function GenerateBaseKey ( $sServerKeyText )
{
	$sRandomKeyText = base64url_encode(random_bytes(32)) . $sServerKeyText;
	$sRandomKeyText = hash ( 'sha512', $sRandomKeyText );
	for ($iIndex=0;$iIndex<20;$iIndex++)
	{
		$sRandomKeyText.= base64url_encode(random_bytes(32));
		$sRandomKeyText = hash ( 'sha512', $sRandomKeyText ) . $sRandomKeyText;
	}
	$sRandomKeyText = hash( 'sha256', $sRandomKeyText, true );
	return substr ( $sRandomKeyText, 0, 16 );
}
