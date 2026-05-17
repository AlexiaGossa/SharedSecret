
function GenerateRandomHeadText ( )
{
	const bRandom = new Uint8Array ( 32 );
	crypto.getRandomValues ( bRandom );
	
	return arrayBufferToBase64Url ( bRandom ).slice ( 0, 32 );
}

function GenerateKey ( )
{
	const bRandom = new Uint8Array ( 32 );
	crypto.getRandomValues ( bRandom );
	
	return bRandom;
}

async function sha256HexText ( bData )
{
	const hashBuffer = await crypto.subtle.digest ( 'SHA-256', bData );
	const hashBytes = new Uint8Array ( hashBuffer );
  
	return Array.from ( hashBytes, b => b.toString ( 16 ).padStart ( 2, '0' ) ).join ( '' );
}

async function sha256Bytes ( bData )
{
	const bHashBuffer = await crypto.subtle.digest ( 'SHA-256', bData );
	return new Uint8Array ( bHashBuffer );
}

async function sha512Bytes ( bData )
{
	const bHashBuffer = await crypto.subtle.digest ( "SHA-512", bData );
	return new Uint8Array ( bHashBuffer );
}

function concatUint8Arrays ( bArrayA, bArrayB )
{
	const bArrayOutput = new Uint8Array ( bArrayA.length + bArrayB.length );
	bArrayOutput.set ( bArrayA, 0 );
	bArrayOutput.set ( bArrayB, bArrayA.length );
	return bArrayOutput;
}

async function CreatePrivateKey ( bServerKey, bLocalKey, sSecretKey )
{
	const bConcat = new Uint8Array ( bServerKey.length + bLocalKey.length + sSecretKey.length );
	bConcat.set ( bServerKey, 0 );
	bConcat.set ( bLocalKey, bServerKey.length );
	bConcat.set ( sSecretKey, bServerKey.length + bLocalKey.length );
	
	const bBuffer = await sha256Bytes ( bConcat );
	const bReturn = new Uint8Array ( bBuffer );
	return bReturn;
}

function arrayBufferToBase64Url ( bArrayBuffer ) 
{
	var sBinary;
	var bData;
	var bStream;

	bStream = bArrayBuffer instanceof Uint8Array ? bArrayBuffer : new Uint8Array ( bArrayBuffer );
	sBinary = "";
  
	for ( bData of bStream )
	{
		sBinary += String.fromCharCode ( bData );
	}

	return btoa ( sBinary )
		.replace ( /\+/g, "-" )
		.replace ( /\//g, "_" )
		.replace ( /=+$/, "" );
}

function base64UrlToUint8Array ( sBase64Url )
{
	var sBase64;
	var iIndex;

	sBase64 = sBase64Url
		.replace ( /-/g, "+" )
		.replace ( /_/g, "/" );
	while ( sBase64.length % 4 )
	{
		sBase64 += "=";
	}

	const bData = atob ( sBase64 );
	const bArrayData = new Uint8Array ( bData.length );

	for ( iIndex=0; iIndex < bData.length; iIndex++ )
	{
		bArrayData[iIndex] = bData.charCodeAt(iIndex);
	}

	return bArrayData;
}  

async function sha512ServerKeyAndRemoveSecretPassword ( bServerKey, sRemoveSecretPassword )
{
	const bRemoveSecretPassword = new TextEncoder().encode( sRemoveSecretPassword );
	const bData = concatUint8Arrays ( bServerKey, bRemoveSecretPassword );
	return await sha512Bytes ( bData );
}

async function GenerateLink ( )
{
	var sSecretText = "";
	var sSecretPassword = "";
	var sRemoveSecretPassword = "";
	var sSecretExpire = "";
	var bRandomKey;
	var bPrivateKey;
	var bCryptoKey;
	
	//On récupère le texte à chiffrer
	sSecretText = $("#secret_text").val();
	const oEncoder = new TextEncoder ( );
	const oEncodedText = await oEncoder.encode ( GenerateRandomHeadText() + sSecretText );
	
	//On récupère le code secret
	sSecretPassword = $("#secret_password").val();
	
	//On récupère le code de suppression
	sRemoveSecretPassword = $("#remove_secret_password").val();
	
	//On récupère le mode de conservation
	sSecretExpire = $("#block-expire input:checked").attr("expire");
	
	//On récupère la clef du serveur
	const bServerKey = Uint8Array.fromHex(sRandomKeyHexa);
	
	//On génère la clef privée
	bPrivateKey = GenerateKey ( );
	bCryptoKey 	= await CreatePrivateKey ( bServerKey, bPrivateKey, sSecretPassword );
	
//console.log ( "cryptokey : " + arrayBufferToBase64Url ( bCryptoKey ) );
	
	//Prépare l'objet de chiffrement avec la clef
	const oCryptoKey = await crypto.subtle.importKey (
		"raw",
		bCryptoKey,
		{
			name: "AES-GCM",
			length: 256
		},
		false,
		[
			"encrypt", 
			"decrypt"
		]
	);
	
	//Vecteur d'initialisation
	const oInitializationVector = new Uint8Array(12);
	crypto.getRandomValues(oInitializationVector);
	
	//On fabrique le message à chiffrer (avec un SHA256 à la fin)
	const oCryptoBuffer = await crypto.subtle.encrypt (
		{
			name: 		"AES-GCM",
			iv: 		oInitializationVector
		},
		oCryptoKey,
		oEncodedText
	);
	
	//Le code de suppression
	//S'il existe, on va le hasher avec la clef du serveur
	if (sRemoveSecretPassword!="")
	{
		const bRemoveSecretPassword = await sha512ServerKeyAndRemoveSecretPassword ( bServerKey, sRemoveSecretPassword );
		sRemoveSecretPassword = arrayBufferToBase64Url ( bRemoveSecretPassword );
	}
	
	if (sSecretPassword!="")
		sSecretPassword = "yes";
		
	
	var oMessageToServer = {
		serverkey:			arrayBufferToBase64Url(bServerKey),
		iv:					arrayBufferToBase64Url(oInitializationVector),
		data:				arrayBufferToBase64Url(oCryptoBuffer),
		secretpassword:		sSecretPassword,
		expire:				sSecretExpire,
		removepassword:		sRemoveSecretPassword	
	};
	
	const sPostMessage = JSON.stringify ( oMessageToServer );
	
	
	//Help here : https://api.jquery.com/jQuery.ajax/#jQuery-ajax-settings
	$.ajax (
		{
			type: "POST",
			url: "/?store",
			data: sPostMessage,
			dataType: "text"
		} 
	).done (
		function ( data, textStatus, jqXHR )
		{
			//$("#secret_url").text(location.href + oMessageToServer.serverkey + "#" + arrayBufferToBase64Url(bPrivateKey) );
			sURL = location.href + oMessageToServer.serverkey + "#" + arrayBufferToBase64Url(bPrivateKey);
			$("#secret_url").attr ( "href", sURL );
			$("#secret_url").text ( sURL );
			
			$("#secret_done").show();
			$("#secret_create").hide();
		}
	).fail (
		function ( jqXHR, textStatus, errorThrown )
		{

		}
	);
			

	
}


async function ShowSecretLink ( )
{
	//	On récupère la clef privée se trouvant après l'ancre
	const sPrivateKey = window.location.hash.substring(1);
	const bPrivateKey = base64UrlToUint8Array ( sPrivateKey );
	
	//	On récupère la clef du serveur
	const bServerKey = base64UrlToUint8Array ( sServerKey );

	//	On récupère le mot de passe
	const sSecretPassword = (sSecretPasswordEnabled)?($("#secret_password").val()):("");

	//	On génère la clef de chiffrement/déchiffrement
	const bCryptoKey 	= await CreatePrivateKey ( bServerKey, bPrivateKey, sSecretPassword );
	
//console.log ( "cryptokey : " + arrayBufferToBase64Url ( bCryptoKey ) );	

	//Prépare l'objet de chiffrement avec la clef
	var oCryptoKey = await crypto.subtle.importKey (
		"raw",
		bCryptoKey,
		{
			name: "AES-GCM",
			length: 256
		},
		false,
		[
			"encrypt", 
			"decrypt"
		]
	);
	
	$.ajax (
		{
			type: "POST",
			url: "/?query",
			data: sServerKey,
			dataType: "text"
		} 
	).done (
		async function ( data, textStatus, jqXHR )
		{
			oMessage = JSON.parse(data);
			
			const oInitializationVector = base64UrlToUint8Array ( oMessage.iv );
			const oCryptoBuffer			= base64UrlToUint8Array ( oMessage.data );
			try {
				const oEncodedText = await crypto.subtle.decrypt (
					{
						name: 		"AES-GCM",
						iv: 		oInitializationVector
					},
					oCryptoKey,
					oCryptoBuffer
				);
			
				var sPlainText = new TextDecoder().decode(oEncodedText).substr(32);
			
				$("#secret_text").text(sPlainText);
				$("#secret_text").show();
				
				$("#show-secretpassword").hide();
				$("#button-show-secret").hide();
				
				
				if (sExpire=="ondemand")
				{
					$("#block-remove_secret").show();
					
					if (sRemovePasswordEnabled=="yes")
					{
						$("#show-remove_secretpassword").show();
					}
					
				}
			} catch (e) {
				
			}
		}
	).fail (
		function ( jqXHR, textStatus, errorThrown )
		{
			console.log ( "error sent" );
			console.log ( textStatus );
		}
	);
	
	
	
	
	
	
}



function UpdateRemoveSecret ( )
{
	if ($('#block-expire #btnradio-ondemand').prop('checked')==true)
	{
		$('#block-remove_secret').css("display", "" );
	}
	else
	{
		$('#block-remove_secret').css("display", "none" );
	}
	
	if ($('#block-expire #btnradio-1read').prop('checked')==true)
	{
		$('#block-secret_password').css("display", "none" );
	}
	else
	{
		$('#block-secret_password').css("display", "" );
	}
	
}


window.onpageshow = function(event) 
{
	$('.btn-check').on('change', function ( ) {
		UpdateRemoveSecret ( );
	} );
	UpdateRemoveSecret ( );
	
	
}

