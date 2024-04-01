<?php
/**
 * SecuPress Template Name: Warning Template
 * 
 * @since 2.2.5.2 Julio Potier
 * @since 1.0 Grégory Viguier
 * 
 * @see secupress_blackhole_please_click_me()
*/
defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );

define( 'DONOTCACHEPAGE', true );

$title = __( 'Warning - Deceptive content', 'secupress' );

?><!DOCTYPE html>
<html <?php language_attributes(); ?>>
	<head>
		<meta charset="<?php echo esc_attr( strtolower( get_bloginfo( 'charset' ) ) ); ?>" />
		<title><?php echo $title; ?></title>
		<meta content="noindex,nofollow" name="robots" />
		<meta content="initial-scale=1.0" name="viewport" />
	    <style>
	        body {
	            margin: 0;
	            padding: 0;
	            font-family: sans-serif;
	            background-color: #C44;
	            display: flex;
	            justify-content: center;
	            align-items: center;
	            height: 50vh;
	        }

	        .warning {
	            text-align: center;
	            background-color: #fee;
	            padding: 40px;
	            border-radius: 12px;
	            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4);
	        }

	        .warning h1 {
	            color: #db4437;
	            margin-bottom: 10px;
	        }

	        .warning p {
	            color: #333;
	            font-size: 16px;
	            margin-top: 10px;
	            line-height: 2em;
	        }

	      blink {
	         animation: blinker-two 1s linear infinite;
	       }
	       @keyframes blinker-two {  
	         100% { opacity: 0; }
	       }
       </style>
</head>
<body>
    <div class="warning">
        <h1><blink><?php echo $title; ?></blink></h1>
		<p><?php
		printf(
			/** Translators: 1 is a file name, 2 is a "click here" link. */
			__( 'The purpose of this page is to detect robots that do not adhere to the rules outlined in the %1$s file.<br><strong>%2$s, or you will be banned from this site.</strong>', 'secupress' ),
			'<code>robots.txt</code>',
			'<a href="' . esc_url( wp_nonce_url( '', 'ban_me_please-' . date( 'ymdhi' ), 'token' ) ) . '">' . __( 'DO NOT CLICK THIS LINK', 'secupress' ) . '</a>'
		);
		?></p>
    </div>
</body>
</html><?php
die();