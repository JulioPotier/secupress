<?php
/*
Module Name: Fight Spam but strongly
Description: The Secupress Anti Spam module
Main Module: antispam
Author: SecuPress
Version: 1.0
*/

defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );


add_filter( 'preprocess_comment', 'secupress_dont_use_my_identity_to_comment' );

function secupress_dont_use_my_identity_to_comment( $commentdata ) {
	global $wpdb;

	if ( is_user_logged_in() || '' !== $commentdata['comment_type'] ) {
		return $commentdata;
	}

	$user = false;

	if ( '' !== $commentdata['comment_author'] ) {
		$user = get_user_by( 'slug', $commentdata['comment_author'] );

		if ( ! $user ) {
			$user = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM $wpdb->users WHERE display_name = %s", $commentdata['comment_author'] ) );
		}
	}

	if ( ! $user && '' !== $commentdata['comment_author_email'] ) {
		$user = get_user_by( 'email', $commentdata['comment_author_email'] );
	}

	if ( $user ) {
		secupress_block( 'Antispam-Anti-Usurpation' );
	}

	return $commentdata;
}


add_filter( 'pre_comment_approved', 'secupress_prevoid_comment', 9, 2 );

function secupress_prevoid_comment( $approved, $commentdata ) {

	$action = secupress_get_module_option( 'antispam_mark-as', 'deletenow', 'antispam' ) === 'deletenow' ? 'trash' : 'spam';

	if ( $action === $approved ) {
		return $approved;
	}

	$approved = 'blacklisted' === secupress_get_spam_status( $commentdata['comment_author_IP'] ) ? $action : $approved;

	if ( $action === $approved ) {
		return $approved;
	}

	$approved = 'blacklisted' === secupress_get_spam_status( $commentdata['comment_author'] ) ? $action : $approved;

	if ( $action === $approved ) {
		return $approved;
	}

	$approved = 'blacklisted' === secupress_get_spam_status( $commentdata['comment_author_email'] ) ? $action : $approved;

	if ( $action === $approved ) {
		return $approved;
	}

	$approved = 'blacklisted' === secupress_get_spam_status( $commentdata['comment_author_url'] ) ? $action : $approved;

	secupress_antispam_set_comment_meta( $approved );

	return $approved;
}


/**
 * Trash any pingback and trackback comments.
 *
 * @since 1.0
 */
add_filter( 'pre_comment_approved', 'secupress_trash_pingbacks_trackbacks', 10, 2 );

function secupress_trash_pingbacks_trackbacks( $approved, $commentdata ) {
	if ( 'trash' === $approved ) {
		return $approved;
	}

	if ( '' !== $commentdata['comment_type'] && secupress_get_module_option( 'antispam_pings-trackbacks', 'mark-ptb', 'antispam' ) === 'forbid-ptb' ) {
		$approved = 'trash';
		do_action( 'secupress.antispam.block', 'pingback+trackback', $approved );
	}

	secupress_antispam_set_comment_meta( $approved );
	return $approved;
}


/**
 * Mark shortcodes as spam.
 *
 * @since 1.0
 */
add_filter( 'pre_comment_approved', 'secupress_shortcode_as_spam_check', 10, 2 );

function secupress_shortcode_as_spam_check( $approved, $commentdata ) {
	if ( 'trash' === $approved || 'spam' === $approved ) {
		return $approved;
	}

	if ( (bool) secupress_get_module_option( 'antispam_shortcode-as-spam', false, 'antispam' ) ) {
		$comment_filtered = preg_replace( '#\[[^\]]+\]#', '', $commentdata->comment_text );

		if ( $commentdata->comment_text !== $comment_filtered ) {
			$approved = secupress_get_module_option( 'antispam_mark-as', 'deletenow', 'antispam' ) === 'deletenow' ? 'trash' : 'spam';
			do_action( 'secupress.antispam.block', 'shortcode-as-spam', $approved );
		}
	}

	secupress_antispam_set_comment_meta( $approved );
	return $approved;
}


add_filter( 'pre_comment_approved', 'secupress_use_wp_blacklist_check_filter', 10, 2 );

function secupress_use_wp_blacklist_check_filter( $approved, $commentdata ) {
	if ( 'trash' === $approved || 'spam' === $approved ) {
		return $approved;
	}

	$user = get_user_by( 'email', $commentdata['comment_author_email'] );

	if ( ! is_wp_error( $user ) || ! user_can( $user, 'moderate_comments' ) ) {
		add_filter( 'pre_option_comment_moderation', '__return_false', 1 );
		$approved = check_comment( $commentdata['comment_author'], $commentdata['comment_author_email'], $commentdata['comment_author_url'], $commentdata['comment_content'], $commentdata['comment_author_IP'], $commentdata['comment_agent'], $commentdata['comment_type'] ) ? 1 : 0;

		do_action( 'secupress.antispam.block', 'moderation_check', $approved );
		remove_filter( 'pre_option_comment_moderation', '__return_false', 1 );
	}

	if ( secupress_get_module_option( 'antispam_better-blacklist-comment', false, 'antispam' ) ) {
		add_filter( 'pre_option_blacklist_keys', '__secupress_antispam_better_blacklist_comment' );
	}

	$action   = secupress_get_module_option( 'antispam_mark-as', 'deletenow', 'antispam' ) === 'deletenow' ? 'trash' : 'spam';
	$approved = wp_blacklist_check( $commentdata['comment_author'], $commentdata['comment_author_email'], $commentdata['comment_author_url'], $commentdata['comment_content'], $commentdata['comment_author_IP'], $commentdata['comment_agent'] ) ? 'trash' : $approved;

	do_action( 'secupress.antispam.block', 'blacklist_check', $approved );

	secupress_antispam_set_comment_meta( $approved );
	return $approved;
}


function __secupress_antispam_better_blacklist_comment( $value ) {
	$file = SECUPRESS_INC_PATH . 'data/spam-blacklist.data';

	if ( is_readable( $file ) ) {
		$spam_words = file( $file );
		$value .= implode( "\n", $spam_words );
	}

	return $value;
}


/**
 * Disable pingbacks/trackbacks.
 *
 * @since 1.0
 */
if ( 'forbid-ptb' === secupress_get_module_option( 'antispam_pings-trackbacks', 'mark-ptb', 'antispam' ) ) :

	add_filter( 'xmlrpc_methods', 'secupress_block_xmlrpc_pingbacks' );

	function secupress_block_xmlrpc_pingbacks( $methods ) {
		unset( $methods['pingback.ping'], $methods['pingback.extensions.getPingbacks'] );
		return $methods;
	}


	add_filter( 'wp_headers', 'secupress_remove_x_pingback_header' );

	function secupress_remove_x_pingback_header( $headers ) {
		unset( $headers['X-Pingback'] );
		return $headers;
	}


	add_filter( 'comments_array' , 'secupress_remove_pingbacks_from_comments' );

	function secupress_remove_pingbacks_from_comments( $comments ) {
		return array_filter( $comments, '__secupress_filter_real_comments' );
	}


	add_filter( 'get_comments_number', 'secupress_comment_count_without_pingbacks', 10, 2 );

	function secupress_comment_count_without_pingbacks( $count, $post_id ) {
		$comments = get_approved_comments( $post_id );
		return count( array_filter( $comments, '__secupress_filter_real_comments' ) );
	}


	function __secupress_filter_real_comments( $comment ) {
		return ! $comment->comment_type;
	}

endif;


/**
 * Get spam status from IP or URL, returning a string "blacklisted" or "safe" or "error".
 *
 * @since 1.0
 *
 * @return (string)
 */
function secupress_get_spam_status( $value ) {
	if ( '' === $value || '::1' === $value || '127.0.0.1' === $value || 0 === strpos( $value, home_url() ) ) {
		return 'safe';
	}

	$spam_cache = get_option( 'secupress_antispam_cache', array() );

	foreach ( $spam_cache as $key => $data ) {
		if ( time() > $spam_cache[ $key ]['timestamp'] ) {
			unset( $spam_cache[ $key ] );
		}
	}
	unset( $key );

	$is_url = false;
	$status = 'error';

	if ( 'http:' === substr( $value, 0, 5 ) || 'https:' === substr( $value, 0, 6 ) ) {
		$value  = parse_url( $value );
		$value  = isset( $value['host'] ) ? $value['host'] : false;
		$is_url = true;
	}

	$key = md5( $value ); // md5 to avoid keeping readable data in DB (ip & email)

	if ( false !== $value && isset( $spam_cache[ $key ] ) && time() < $spam_cache[ $key ]['timestamp'] ) {
		return $spam_cache[ $key ]['status'];
	}

	if ( false !== $value && $is_url ) {

		$service_base_url = 'http://www.urlvoid.com/';

		// First scan to initialize the entry if new
		$url = $service_base_url . 'scan/' . $value;
		wp_remote_get( $url, array( 'timeout' => 2, 'blocking' => false ) );

		// Force update the entry
		$url = $service_base_url . 'update-report/' . $value;
		wp_remote_get( $url, array( 'timeout' => 10 ) );

		// Scan the entry, updated
		$url      = $service_base_url . 'scan/' . $value;
		$response = wp_remote_get( $url, array( 'timeout' => 10 ) );

		// Manage to get the status doing a parsing job
		if ( ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response ) ) {

			if ( strpos( $response['body'], '<span class="label label-success">' ) > 0 ) {
				$status = 'safe';
			} else {
				$status = 'blacklisted';

				do_action( 'secupress.commentspam.blacklisted', $value );
			}

			$spam_cache[ $key ] = array( 'timestamp' => time() + 30 * DAY_IN_SECONDS, 'status' => $status );
			update_option( 'secupress_antispam_cache', $spam_cache );

		}

	} else { // IP, Email, Username

		$service_base_url = 'http://www.stopforumspam.com/search?export=serial&q=';
		$response         = wp_remote_get( $service_base_url . $value, array( 'timeout' => 5 ) );

		if ( ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response ) ) {
			$results = unserialize( $response['body'] );

			if ( isset( $results[0] ) ) {
				$status = 'blacklisted';
				do_action( 'secupress.commentspam.blacklisted', $value );
			} else {
				$status = 'safe';
			}

			$spam_cache[ $key ] = array( 'timestamp' => time() + 30 * DAY_IN_SECONDS, 'status' => $status );
			update_option( 'secupress_antispam_cache', $spam_cache );
		}
	}

	return $status;
}


add_action( 'admin_print_scripts-post.php', 'secupress_antispam_no_pingstatus_css' );

function secupress_antispam_no_pingstatus_css() {
	if ( secupress_get_module_option( 'antispam_pings-trackbacks', 'mark-ptb', 'antispam' ) === 'forbid-ptb' ) {
		echo '<style type="text/css">label[for="ping_status"]{display: none;}</style>';
	}
}


function secupress_antispam_set_comment_meta( $comment_id, $approved ) {
	if ( 'trash' === $approved || 'spam' === $approved && false === get_comment_meta( $comment_id, 'secupress_antispam_status' ) ) {
		add_comment_meta( $comment_id, 'secupress_antispam_status', $approved, true );
	}
}
