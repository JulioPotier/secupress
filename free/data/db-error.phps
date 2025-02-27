<?php
/**
 * {{PLUGIN_NAME}} DB Error Bail Message
 * @since 2.2.6
 * @author Julio Potier
 * @license GPLv2
 * @see $wpdb->db_connect()
 * 
 * Copyright 2012-2025 SecuPress
 */

/*/ DO NOT USE OUR TEXTDOMAIN FOR I18N, WE HAVE TO FAKE THE WP ONE HERE /*/

$message  = '<h1>' . __( 'Error establishing a database connection' ) . "</h1>\n";
$message .= '<p>' . sprintf(
	__( 'This either means that the username and password information in your %1$s file is incorrect or that contact with the database server at %2$s could not be established. This could mean your host&#8217;s database server is down.' ),
	'<code>wp-config.php</code>',
	'<code>DB_HOST</code>'
) . "</p>\n";
$message .= "<ul>\n";
$message .= '<li>' . __( 'Are you sure you have the correct username and password?' ) . "</li>\n";
$message .= '<li>' . __( 'Are you sure you have typed the correct hostname?' ) . "</li>\n";
$message .= '<li>' . __( 'Are you sure the database server is running?' ) . "</li>\n";
$message .= "</ul>\n";

$message .= '<p>' . sprintf(
	__( 'If you are unsure what these terms mean you should probably contact your host. If you still need help you can always visit the <a href="%s">WordPress support forums</a>.' ),
	__( 'https://wordpress.org/support/forums/' )
) . "</p>\n";

if ( defined( 'SECUPRESS_LOCKED_ADMIN_EMAIL' ) ) {
	$fname   = ABSPATH . '/.secupress_db_down_flag';
	$content = '';
	if ( @file_exists( $fname ) ) {
		$content = @file_get_contents( $fname, false, null, 0, 10 );
	}
	if ( (int) $content < ( time() - ( 60*60*24 ) ) ) {
		$headers = 'From: no-reply@' . $_SERVER['HTTP_HOST'];
		$sent    = @mail( SECUPRESS_LOCKED_ADMIN_EMAIL, sprintf( 'Website %s down!', $_SERVER['HTTP_HOST'] ), sprintf( 'Website %s is down due to a database error. Please check the server and contact the host.', $_SERVER['HTTP_HOST'] ), $headers );
		@unlink( $fname );
		@file_put_contents( $fname, time() );
	}
}
wp_die( $message );