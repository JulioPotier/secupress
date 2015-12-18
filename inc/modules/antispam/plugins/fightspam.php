<?php
/*
Module Name: Fight Spam!
Description: The Secupress Anti Spam module
Main Module: antispam
Author: SecuPress
Version: 1.0
*/
defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' ); 

add_filter( 'pre_comment_approved', 'secupress_trash_pingbacks_trackbacks', 10, 2 );
function secupress_trash_pingbacks_trackbacks( $approved, $commentdata ) {
	// Trash any pingback and trackback comments
	if ( '' != $commentdata['comment_type'] && secupress_get_module_option( 'antispam_pings-trackbacks', 'mark-ptb', 'antispam' ) == 'forbid-ptb' ) {
		$approved = 'trash';
		do_action( 'secupress.antispam.block', 'pingback+trackback', $approved );
	}
	return $approved;
}

add_filter( 'pre_comment_approved', 'secupress_shortcode_as_spam_check', 10, 2 );
function secupress_shortcode_as_spam_check( $approved, $commentdata ) {
	
	// Mark shortcodes as spam
	if ( (bool) secupress_get_module_option( 'antispam_shortcode-as-spam', false, 'antispam' ) ) {
		$comment_filtered = preg_replace( '#\[[^\]]+\]#', '', $commentdata->comment_text );
		if ( $commentdata->comment_text !== $comment_filtered ) {
			do_action( 'secupress.antispam.block', 'shortcode-as-spam', $approved );
			$approved = secupress_get_module_option( 'antispam_mark-as', 'deletenow', 'antispam' ) == 'deletenow' ? 'trash' : 'spam';
		}
	}
	return $approved;
}

add_filter( 'pre_comment_approved', 'secupress_use_wp_blacklist_check_filter', 10, 2 );
function secupress_use_wp_blacklist_check_filter( $approved, $commentdata ) {

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
	$action = secupress_get_module_option( 'antispam_mark-as', 'deletenow', 'antispam' ) == 'deletenow' ? 'trash' : 'spam';
	$approved = wp_blacklist_check( $commentdata['comment_author'], $commentdata['comment_author_email'], $commentdata['comment_author_url'], $commentdata['comment_content'], $commentdata['comment_author_IP'], $commentdata['comment_agent'] ) ? 'trash' : $approved;
	do_action( 'secupress.antispam.block', 'blacklist_check', $approved );

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

// Disable pingbacks/trackbacks
if ( 'forbid-ptb' == secupress_get_module_option( 'antispam_pings-trackbacks', 'mark-ptb', 'antispam' ) ) :

	add_filter( 'xmlrpc_methods', 'secupress_block_xmlrpc_pingbacks' );
	function secupress_block_xmlrpc_pingbacks( $methods ) {
		unset( $methods['pingback.ping'] );
		unset( $methods['pingback.extensions.getPingbacks'] );
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