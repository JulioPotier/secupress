<?php
/**
 * Module Name: Fight Spam but strongly
 * Description: The Secupress Anti Spam module
 * Main Module: antispam
 * Author: SecuPress
 * Version: 1.0.3
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );


/** --------------------------------------------------------------------------------------------- */
/** ANTI-USURPATION ============================================================================= */
/** --------------------------------------------------------------------------------------------- */

add_filter( 'preprocess_comment', 'secupress_fightspam_dont_use_my_identity_to_comment' );
/**
 * Prevent logged out users to use registered users identity to comment.
 *
 * @since 1.0
 *
 * @param (array) $commentdata Comment data.
 *
 * @return (array) $commentdata Comment data.
 */
function secupress_fightspam_dont_use_my_identity_to_comment( $commentdata ) {
	global $wpdb;

	if ( is_user_logged_in() || ! empty( $commentdata['comment_type'] ) ) {
		return $commentdata;
	}

	$user = false;

	// Test with author username.
	if ( ! empty( $commentdata['comment_author'] ) ) {
		$user = get_user_by( 'slug', $commentdata['comment_author'] );

		if ( ! $user ) {
			$user = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM $wpdb->users WHERE display_name = %s", $commentdata['comment_author'] ) );
		}
	}

	// Test with author email address.
	if ( ! $user && ! empty( $commentdata['comment_author_email'] ) ) {
		$user = get_user_by( 'email', $commentdata['comment_author_email'] );
	}

	// If the user exists, don't process.
	if ( $user ) {
		// Add some CSS style for the textarea.
		add_filter( 'secupress.die.message', 'secupress_fightspam_die_message_content_filter' );

		$content = sprintf(
			/* translators: %s is a "please log in" link */
			__( 'Can’t process because this username or email belongs to a registered user. If it’s you, %s.', 'secupress' ),
			'<a href="' . esc_url( wp_login_url( wp_get_referer() ) ) . '">' . __( 'please log in', 'secupress' ) . '</a>'
		);
		if ( ! empty( $commentdata['comment_content'] ) ) {
			$content .= "<br/>\n";
			$content .= __( 'You may want to copy your message before logging in:', 'secupress' );
			$content .= '<br/><textarea readonly="readonly" rows="8" cols="45">' . esc_html( wp_unslash( $commentdata['comment_content'] ) ) . '</textarea>';
		}

		secupress_block( 'AAU', $content );
	}

	return $commentdata;
}


/**
 * Filter the message displayed when a logged out user tries to use a registered user identity.
 * Add some CSS style to the textarea.
 *
 * @since 1.0
 *
 * @param (string) $message The message.
 *
 * @return (string) The message.
 */
function secupress_fightspam_die_message_content_filter( $message ) {
	$message = '<style type="text/css">textarea {
	box-sizing: border-box;
	width: 100%;
	padding: .5em;
	margin-top: 1em;
	font-family: Arial, Helvetica, sans-serif;
	color: #222;
	font-size: inherit;
	line-height: inherit;
	word-wrap: break-word;
	  -epub-hyphens: auto;
	-webkit-hyphens: auto;
	   -moz-hyphens: auto;
	    -ms-hyphens: auto;
	        hyphens: auto;
}</style>' . $message;
	return $message;
}


/** --------------------------------------------------------------------------------------------- */
/** FIGHT SPAM ================================================================================== */
/** --------------------------------------------------------------------------------------------- */

add_action( 'check_comment_flood', 'secupress_fightspam_force_check_comment' );
/**
 * Force deactivation of "manual comment moderation" option.
 * Force deactivation of "approve comments by previously-approved authors" option.
 * This will allow `check_comment()` to run its tests properly in `wp_allow_comment()`, and let us do our job.
 * Force deactivation of the blacklist from WordPress, because it does not return the right spam status. We will use it later in `secupress_fightspam_blacklist_as_spam_check()`.
 *
 * @since 2.0 Remove pre_option_comment_moderation
 * @since 1.0
 */
function secupress_fightspam_force_check_comment() {
	if ( get_option( 'comment_moderation' ) ) {
		// Do not use `__return_false`, it won't work.
		// add_filter( 'pre_option_comment_moderation', '__return_zero', 1 );
		add_filter( 'pre_option_comment_whitelist',  '__return_empty_string', 1 );
		add_filter( 'pre_option_blacklist_keys',     '__return_empty_string', 1 );
	}
}


add_filter( 'pre_comment_approved', 'secupress_fightspam_set_logged_in_comment_status', 0, 2 );
/**
 * Set the comment status to return when the user is logged in.
 *
 * @since 1.2.3
 * @author Grégory Viguier
 *
 * @param (int|string) $approved    The approval status. Accepts 1, 0, 'spam', or 'trash'.
 * @param (array)      $commentdata Comment data.
 *
 * @return (int|string) 1, 0, 'spam', or 'trash'.
 */
function secupress_fightspam_set_logged_in_comment_status( $approved, $commentdata ) {
	if ( ! is_user_logged_in() ) {
		return $approved;
	}

	$comment_status = 1;
	/**
	 * Filter the comment status to return when the user is logged in.
	 *
	 * @since 1.2.3
	 * @author Grégory Viguier
	 *
	 * @param (int|string) $comment_status The approval status. Accepts 1, 0, 'spam', or 'trash'. Default to 1.
	 * @param (int|string) $approved       The original approval status. Accepts 1, 0, 'spam', or 'trash'.
	 * @param (array)      $commentdata    Comment data.
	 */
	return apply_filters( 'secupress_fightspam_logged_in_comment_status', $comment_status, $approved, $commentdata );
}


add_filter( 'pre_comment_approved', 'secupress_fightspam_remove_comment_moderation_filter', 0 );
/**
 * Replace status 0 (pending) returned by `check_comment()` by our own status (`trash` or `spam`).
 * Remove our filter that forces deactivation of "manual comment moderation" option.
 * Remove our filter that forces deactivation of "approve comments by previously-approved authors" option.
 *
 * @since 1.0
 *
 * @param (int|string) $approved The approval status. Accepts 1, 0, 'spam', or 'trash'.
 *
 * @return (int|string) 1, 0, 'spam', or 'trash'.
 */
function secupress_fightspam_remove_comment_moderation_filter( $approved ) {
	// Remove our filters.
	remove_filter( 'pre_option_comment_moderation', '__return_zero', 1 );
	remove_filter( 'pre_option_comment_whitelist',  '__return_empty_string', 1 );
	remove_filter( 'pre_option_blacklist_keys',     '__return_empty_string', 1 );

	if ( is_user_logged_in() ) {
		return $approved;
	}

	// Replace status 0 returned by `check_comment()` by our own status (`trash` or `spam`).
	if ( 'trash' === $approved || 'spam' === $approved ) {
		return secupress_fightspam_return_spam_status_setting( 'moderation' );
	}

	return $approved;
}


add_filter( 'pre_comment_approved', 'secupress_fightspam_author_as_spam_check', 9, 2 );
/**
 * Mark a comment as spam, depending on its author IP, username, email, and URL.
 *
 * @since 1.0
 *
 * @param (int|string) $approved    The approval status. Accepts 1, 0, 'spam', or 'trash'.
 * @param (array)      $commentdata Comment data.
 *
 * @return (int|string) 1, 0, 'spam', or 'trash'.
 */
function secupress_fightspam_author_as_spam_check( $approved, $commentdata ) {
	if ( is_user_logged_in() ) {
		return $approved;
	}

	if ( 'trash' === $approved || 'spam' === $approved || ! secupress_fightspam_needs_spam_check( $commentdata ) ) {
		return $approved;
	}

	// IP.
	$status = secupress_fightspam_get_spam_status( $commentdata['comment_author_IP'] );
	if ( 'error' === $status ) {
		// The "Error" status does not exist, we use "Pending" instead.
		return 0;
	}
	if ( 'blacklisted' === $status ) {
		// This seems to be a spam.
		return secupress_fightspam_return_spam_status_setting( 'ip' );
	}

	// // Username.
	// $status = secupress_fightspam_get_spam_status( $commentdata['comment_author'] );

	// if ( 'error' === $status ) {
	// 	return 0;
	// }
	// if ( 'blacklisted' === $status ) {
	// 	return secupress_fightspam_return_spam_status_setting( 'username' );
	// }

	// Email.
	$status = secupress_fightspam_get_spam_status( $commentdata['comment_author_email'] );

	if ( 'error' === $status ) {
		return 0;
	}
	if ( 'blacklisted' === $status ) {
		return secupress_fightspam_return_spam_status_setting( 'email' );
	}

	// URL.
	$status = secupress_fightspam_get_spam_status( $commentdata['comment_author_url'] );

	if ( 'error' === $status ) {
		return 0;
	}
	if ( 'blacklisted' === $status ) {
		return secupress_fightspam_return_spam_status_setting( 'url' );
	}

	return $approved;
}


add_filter( 'pre_comment_approved', 'secupress_fightspam_shortcode_as_spam_check', 9, 2 );
/**
 * Mark comments with shortcodes or BBcodes as spam.
 *
 * @since 1.0
 *
 * @param (int|string) $approved    The approval status. Accepts 1, 0, 'spam', or 'trash'.
 * @param (array)      $commentdata Comment data.
 *
 * @return (int|string) 1, 0, 'spam', or 'trash'.
 */
function secupress_fightspam_shortcode_as_spam_check( $approved, $commentdata ) {
	if ( is_user_logged_in() ) {
		return $approved;
	}

	if ( 'trash' === $approved || 'spam' === $approved || ! secupress_fightspam_needs_spam_check( $commentdata ) ) {
		return $approved;
	}

	if ( ! secupress_get_module_option( 'antispam_shortcode-as-spam', false, 'antispam' ) ) {
		return $approved;
	}

	$comment_filtered = preg_replace( '#\[[^\]]+\]#', '', $commentdata->comment_text );

	if ( $commentdata->comment_text !== $comment_filtered ) {
		return secupress_fightspam_return_spam_status_setting( 'shortcode' );
	}

	return $approved;
}


add_filter( 'pre_comment_approved', 'secupress_fightspam_blacklist_as_spam_check', 9, 2 );
/**
 * Mark comments as spam, depending on a blacklist.
 * The blacklist from WordPress is disabled in `secupress_fightspam_force_check_comment()`. We run the test here (with maybe our improved list).
 *
 * @since 1.0
 *
 * @param (int|string) $approved    The approval status. Accepts 1, 0, 'spam', or 'trash'.
 * @param (array)      $commentdata Comment data.
 *
 * @return (int|string) 1, 0, 'spam', or 'trash'.
 */
function secupress_fightspam_blacklist_as_spam_check( $approved, $commentdata ) {
	if ( is_user_logged_in() ) {
		return $approved;
	}

	if ( 'trash' === $approved || 'spam' === $approved || ! secupress_fightspam_needs_spam_check( $commentdata ) ) {
		return $approved;
	}

	if ( secupress_get_module_option( 'antispam_better-blacklist-comment', false, 'antispam' ) ) {
		// Add our blacklist.
		add_filter( 'pre_option_blacklist_keys', 'secupress_fightspam_better_blacklist_comment' );
	}

	// Test.
	if ( wp_check_comment_disallowed_list(
		$commentdata['comment_author'],
		$commentdata['comment_author_email'],
		$commentdata['comment_author_url'],
		$commentdata['comment_content'],
		$commentdata['comment_author_IP'],
		$commentdata['comment_agent']
	) ) {
		return secupress_fightspam_return_spam_status_setting( 'blacklist' );
	}

	remove_filter( 'pre_option_blacklist_keys', 'secupress_fightspam_better_blacklist_comment' );

	return $approved;
}


/**
 * Add our blacklist to the WordPress's one.
 *
 * @since 1.0
 *
 * @param (bool|string) $value The value of the WordPress's blacklist.
 *
 * @return (string) The blacklist.
 */
function secupress_fightspam_better_blacklist_comment( $value ) {
	$file = SECUPRESS_INC_PATH . 'data/spam-blacklist.data';

	if ( is_readable( $file ) ) {
		$spam_words = file( $file );
		$value     .= "\n" . implode( "\n", $spam_words );
	}

	return trim( $value );
}


add_action( 'secupress.plugins.loaded', 'secupress_fightspam_maybe_disable_trackbaks' );
/**
 * Disable pingbacks/trackbacks.
 *
 * @since 1.0
 */
function secupress_fightspam_maybe_disable_trackbaks() {
	if ( ! secupress_get_module_option( 'antispam_forbid-pings-trackbacks', 0, 'antispam' ) ) {
		return;
	}

	add_filter( 'xmlrpc_methods',               'secupress_fightspam_block_xmlrpc_pingbacks' );
	add_filter( 'wp_headers',                   'secupress_fightspam_remove_x_pingback_header' );
	add_filter( 'comments_array' ,              'secupress_fightspam_remove_pingbacks_from_comments' );
	add_filter( 'get_comments_number',          'secupress_fightspam_comment_count_without_pingbacks', 10, 2 );
	add_action( 'admin_print_scripts-post.php', 'secupress_fightspam_no_pingstatus_css' );
}


/**
 * Remove the `pingback.ping` and `pingback.extensions.getPingbacks` xmlrpc methods.
 *
 * @since 1.0
 *
 * @param (array) $methods Methods.
 *
 * @return (array)
 */
function secupress_fightspam_block_xmlrpc_pingbacks( $methods ) {
	unset( $methods['pingback.ping'], $methods['pingback.extensions.getPingbacks'] );
	return $methods;
}


/**
 * Remove the `X-Pingback` header.
 *
 * @since 1.0
 *
 * @param (array) $headers Headers set by WordPress.
 *
 * @return (array)
 */
function secupress_fightspam_remove_x_pingback_header( $headers ) {
	unset( $headers['X-Pingback'] );
	return $headers;
}


/**
 * Remove pingbacks from comments.
 *
 * @since 1.0
 *
 * @param (array) $comments Comments.
 *
 * @return (array)
 */
function secupress_fightspam_remove_pingbacks_from_comments( $comments ) {
	return array_filter( $comments, 'secupress_fightspam_filter_real_comments' );
}


/**
 * Remove pingbacks from the comments count.
 *
 * @since 1.0
 *
 * @param (int) $count   Comments count.
 * @param (int) $post_id Post ID.
 *
 * @return (int)
 */
function secupress_fightspam_comment_count_without_pingbacks( $count, $post_id ) {
	$comments = get_approved_comments( $post_id );
	$comments = array_filter( $comments, 'secupress_fightspam_filter_real_comments' );
	return count( $comments );
}


/**
 * Used as callback for `array_filter()` to remove pingbacks from an array of comments.
 *
 * @since 1.0
 *
 * @param (array) $comment A comment.
 *
 * @return (array)
 */
function secupress_fightspam_filter_real_comments( $comment ) {
	return ! ( 'Pingback' === $comment->comment_type || 'Trackback' === $comment->comment_type );
}


/**
 * Print some CSS to hide the pingback checkbox in the Post edition window.
 *
 * @since 1.0
 */
function secupress_fightspam_no_pingstatus_css() {
	echo '<style type="text/css">label[for="ping_status"]{display: none;}</style>';
}


/** --------------------------------------------------------------------------------------------- */
/** HANDLING ERRORS ============================================================================= */
/** --------------------------------------------------------------------------------------------- */

add_action( 'comment_post', 'secupress_fightspam_maybe_schedule_retest', 10, 2 );
/**
 * Fires immediately after a comment is inserted into the database.
 * If a comment is not approved (`$comment_approved` value is 0), that means the service we rely on was unavailable at the moment.
 * In that case we schedule another test few minutes later.
 *
 * @since 1.0
 *
 * @param (int)        $comment_id       The comment ID.
 * @param (int|string) $comment_approved 1 if the comment is approved, 0 if not, 'spam' if spam, 'trash' if sent directly to trash.
 */
function secupress_fightspam_maybe_schedule_retest( $comment_id, $comment_approved ) {
	if ( 0 !== (int) $comment_approved ) {
		return;
	}

	secupress_fightspam_schedule_retest( $comment_id );
}


/**
 * Schedule a test.
 *
 * @since 1.0
 *
 * @param (int) $comment_id The comment ID.
 */
function secupress_fightspam_schedule_retest( $comment_id ) {
	$tests = secupress_get_transient( 'secupress_fightspam_retests' );
	$tests = is_array( $tests ) ? $tests : array();

	$tests[ $comment_id ] = time();

	secupress_set_transient( 'secupress_fightspam_retests', $tests );
}


add_action( 'secupress.plugins.loaded', 'secupress_fightspam_async_retests_init' );
/**
 * Initiate async retests class.
 *
 * @since 1.0
 */
function secupress_fightspam_async_retests_init() {
	secupress_require_class_async();

	require_once( SECUPRESS_MODULES_PATH . 'antispam/plugins/inc/php/fightspam/class-secupress-background-process-fightspam-retest.php' );

	SecuPress_Background_Process_Fightspam_Retest::get_instance();

	add_action( 'init', 'secupress_fightspam_maybe_do_retests' );
}


/**
 * Maybe process scheduled tests (test them again for spam).
 *
 * @since 1.0
 */
function secupress_fightspam_maybe_do_retests() {
	// Let's see if we have new ones.
	$tests = secupress_get_transient( 'secupress_fightspam_retests' );

	if ( ! $tests || ! is_array( $tests ) ) {
		// No problem.
		return;
	}

	/**
	 * Filter the time between each retest.
	 *
	 * @since 1.0
	 *
	 * @param (int) $time Time in minutes between each retest.
	 */
	$time    = apply_filters( 'secupress.plugin.fightspam.minutes_between_retests', 1 );
	$time    = time() - absint( $time * MINUTE_IN_SECONDS );
	$retests = array();

	foreach ( $tests as $comment_id => $comment_time ) {
		if ( $comment_time <= $time ) {
			// Delay is passed.
			$retests[] = $comment_id;
			unset( $tests[ $comment_id ] );
		}
	}

	if ( ! $retests ) {
		// Nothing to retest yet.
		return;
	}

	// Remove retests from the list.
	if ( $tests ) {
		secupress_set_transient( 'secupress_fightspam_retests', $tests );
	} else {
		secupress_delete_transient( 'secupress_fightspam_retests' );
	}

	// Do retests asynchroniously.
	$process = SecuPress_Background_Process_Fightspam_Retest::get_instance();

	array_map( array( $process, 'push_to_queue' ), $retests );

	$process->save()->dispatch();
}


/** --------------------------------------------------------------------------------------------- */
/** TOOLS ======================================================================================= */
/** --------------------------------------------------------------------------------------------- */

/**
 * Shorthand to get the spam status setting.
 *
 * @since 1.0
 *
 * @return (string) 'spam' or 'trash'.
 */
function secupress_fightspam_get_spam_status_setting() {
	return secupress_get_module_option( 'antispam_mark-as', 'spam', 'antispam' ) === 'trash' ? 'trash' : 'spam';
}


/**
 * Shorthand to get the spam status setting and trigger an action hook before that.
 *
 * @since 1.0
 *
 * @param (string) $context Some context.
 *
 * @return (string) 'spam' or 'trash'.
 */
function secupress_fightspam_return_spam_status_setting( $context ) {
	$approved = secupress_fightspam_get_spam_status_setting();

	/**
	 * Fires before declaring a comment as spam.
	 *
	 * @since 1.0
	 *
	 * @param (string) $context  Some context.
	 * @param (string) $approved The spam status set by the user in the plugin settings.
	 */
	do_action( 'secupress.plugin.fightspam.spam_status', $context, $approved );

	return $approved;
}


/**
 * Tell if spam needs to be tested. This is the same test used in `wp_allow_comment()`.
 *
 * @since 1.0
 *
 * @param (array) $commentdata Comment data.
 *
 * @return (bool) False if the user is the post author or can moderate comments
 */
function secupress_fightspam_needs_spam_check( $commentdata ) {
	global $wpdb;
	static $needs = array();

	if ( ! isset( $commentdata['user_id'], $commentdata['comment_post_ID'] ) ) {
		return true;
	}

	$key = '#' . $commentdata['user_id'] . '#' . $commentdata['comment_post_ID'];

	if ( isset( $needs[ $key ] ) ) {
		return $needs[ $key ];
	}

	if ( ! empty( $commentdata['user_id'] ) ) {
		$user   = get_userdata( $commentdata['user_id'] );
		$author = $wpdb->get_var( $wpdb->prepare( "SELECT post_author FROM $wpdb->posts WHERE ID = %d LIMIT 1", $commentdata['comment_post_ID'] ) );
	}

	if ( isset( $user ) && ( (int) $commentdata['user_id'] === (int) $author || $user->has_cap( 'moderate_comments' ) ) ) {
		// The author and the admins get respect.
		$needs[ $key ] = false;
	} else {
		$needs[ $key ] = true;
	}

	return $needs[ $key ];
}


/**
 * Get spam status.
 *
 * @since 1.0
 *
 * @param (string) $value Username, IP, email, or URL.
 *
 * @return (string) "blacklisted", "safe", or "error".
 */
function secupress_fightspam_get_spam_status( $value ) {
	if ( '' === $value || secupress_ip_is_whitelisted( $value ) || 0 === strpos( $value, home_url() ) ) {
		return 'safe';
	}

	// $spam_cache = secupress_get_transient( 'secupress_fightspam_cache' );
	// $spam_cache = is_array( $spam_cache ) ? $spam_cache : array();

	// if ( $spam_cache ) {
	// 	foreach ( $spam_cache as $key => $data ) {
	// 		if ( time() > $spam_cache[ $key ]['timestamp'] ) {
	// 			unset( $spam_cache[ $key ] );
	// 		}
	// 	}
	// }
	$is_url = false;
	$status = 'error';

	if ( 'http:' === substr( $value, 0, 5 ) || 'https:' === substr( $value, 0, 6 ) ) {
		$value  = wp_parse_url( $value );
		$value  = isset( $value['host'] ) ? $value['host'] : false;
		$is_url = true;
	}

	$key = md5( $value ); // MD5 to avoid keeping readable data in DB (IP & email).

	if ( false !== $value && isset( $spam_cache[ $key ] ) && time() < $spam_cache[ $key ]['timestamp'] ) {
		return $spam_cache[ $key ]['status'];
	}

	// URL.
	if ( false !== $value && $is_url ) {
		$service_base_url = 'http://www.urlvoid.com/';

		// First scan to initialize the entry if new.
		$url = $service_base_url . 'scan/' . $value;
		wp_remote_get( $url, array( 'timeout' => 2, 'blocking' => false ) );

		// Force update the entry.
		$url = $service_base_url . 'update-report/' . $value;
		wp_remote_get( $url, array( 'timeout' => 10 ) );

		// Scan the entry, updated.
		$url      = $service_base_url . 'scan/' . $value;
		$response = wp_remote_get( $url, array( 'timeout' => 10 ) );

		// Manage to get the status doing a parsing job.
		if ( ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response ) ) {

			if ( strpos( $response['body'], '<span class="label label-success">' ) > 0 ) {
				$status = 'safe';
			} else {
				$status = 'blacklisted';
			}
		}
	}
	// IP, Email, Username.
	else {
		$is_what = 'username';
		if ( filter_var( $value, FILTER_VALIDATE_IP ) ) {
			$is_what = 'ip';
		} elseif ( is_email( $value ) ) {
			$is_what = 'email';
		}
		if ( 'username' !== $is_what ) {
			$service_base_url = 'https://api.stopforumspam.org/api?f=serial&' . $is_what . '=' . $value;
			$response         = wp_remote_get( $service_base_url, array( 'timeout' => 5 ) );

			if ( ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response ) ) {
				$results = maybe_unserialize( $response['body'] );

				if ( isset( $results['success'], $results[ $is_what ] ) && $results['success'] ) {
					$status = 0 === (int) $results[ $is_what ]['frequency'] && ( ! isset( $results[ $is_what ]['confidence'] ) || 1 < $results[ $is_what ]['confidence'] ) ? 'safe' : 'blacklisted';
				}
			}
		} else {
			// We can't say "John" is a spammer just by it's name. SO, all username are "good" since they can't be a URL, already done earlier.
			$status = 'safe';
		}
	}

	if ( 'error' !== $status ) {
		if ( 'blacklisted' === $status ) {
			/**
			 * Fires if the status is "blacklisted".
			 *
			 * @since 1.0
			 *
			 * @param (string) $value Username, IP, email, or URL.
			 */
			do_action( 'secupress.plugin.fightspam.comment_blacklisted', $value );
		}

		// Cache the status for 30 days.
		$spam_cache[ $key ] = array( 'timestamp' => time() + 30 * DAY_IN_SECONDS, 'status' => $status );
		secupress_set_transient( 'secupress_fightspam_cache', $spam_cache );
	}

	return $status;
}

add_action( 'wp_footer', 'secupress_fightspam_dont_comment_too_soon_timer' );
/**
 * Add a timer to change and disabled the submit button on the comment form
 *
 * @author Julio Potier
 * @since 2.3
 **/
function secupress_fightspam_dont_comment_too_soon_timer() {
	// Do not do it if the setting is not set
	if ( ! secupress_get_module_option( 'antispam_comment-delay', 1, 'antispam' ) ) {
		return;
	}
	// Only do this if we are on a singular page which supports comments and where comments are open with a non logged in user
	if ( ! is_singular() || is_user_logged_in() || post_type_supports( get_post_type(), 'comments' ) || comments_open() ) {
		return;
	}
	// Set our timer in PHP with a filter
	/**
	 * Filter the default timer, 30 by default
	 */
	$secupress_dcts_timer = (int) apply_filters( 'secupress.plugins.fightspam.comment_timer', 30 );
	// Just check if it's correct (>0)
	if ( $secupress_dcts_timer <= 0 ) {
		return;
	}
	// Get the 2 filtered IDs for the form
	$comment_form_defaults = [ 'id_form' => 'commentform', 'id_submit' => 'submit' ];
	$comment_form_defaults = wp_parse_args( $comment_form_defaults, apply_filters( 'comment_form_defaults', $comment_form_defaults ) );
	?>
	<script>
	//<![CDATA[
	// Get the submit from the WP comment form
	var secupress_dcts_submit = document.getElementById('<?php echo esc_js( $comment_form_defaults['id_form'] ); ?>').querySelectorAll('#<?php echo esc_js( $comment_form_defaults['id_submit'] ); ?>');
	// If there is not, bail.
	if ( secupress_dcts_submit.length ) {
		// Get the button label
		var secupress_dcts_submit_value = secupress_dcts_submit[0].value;
		// Set our timer in JS from our filter
		var secupress_dcts_timer = <?php echo esc_js( $secupress_dcts_timer ); ?>;
		// Disable the button and make it alpha 50%
		secupress_dcts_submit[0].setAttribute("disabled", "");
		secupress_dcts_submit[0].style.opacity = 0.5;
		// Change the label to include the timer at max value
		secupress_dcts_submit[0].value = secupress_dcts_submit[0].value + ' (' + secupress_dcts_timer + ')';
		// Every second, reduce the timer by 1 and print it in the button
		secupress_dcts_submit_interval = setInterval(
			function() {
				secupress_dcts_timer--;
				secupress_dcts_submit[0].value = secupress_dcts_submit_value + ' (' + secupress_dcts_timer + ')';
			},
		1000 );
		// When the timer is done, rset the label, alpha, disabled status of the button
		setTimeout(
			function() { 
				clearInterval( secupress_dcts_submit_interval );
				secupress_dcts_submit[0].value = secupress_dcts_submit_value;
				secupress_dcts_submit[0].removeAttribute("disabled");
				secupress_dcts_submit[0].style.opacity = 1;
			},
		secupress_dcts_timer * 1000 );

	var xmlhttp = new XMLHttpRequest();
	// Do the AJAX request, vanilla style
    xmlhttp.onreadystatechange = function() {
        if (xmlhttp.readyState == XMLHttpRequest.DONE) { // XMLHttpRequest.DONE == 4
           if (xmlhttp.status == 200) {
               document.getElementById("secupress_dcts_timer").value = xmlhttp.responseText;
           }
        }
    };

    xmlhttp.open("GET", "<?php echo esc_js( esc_url( admin_url( 'admin-ajax.php?action=secupress_dcts_timer' ) ) ); ?>", true);
    xmlhttp.send();
	}
	//]]>
	</script>
	<?php
}

add_action( 'comment_form_top', 'secupress_fightspam_dont_comment_too_soon_field' );
/**
 * Add our field at the top of the form
 *
 * @since 2.3
 * @author Julio Potier
 **/
function secupress_fightspam_dont_comment_too_soon_field() {
	// Do not do it if the setting is not set
	if ( ! secupress_get_module_option( 'antispam_comment-delay', 1, 'antispam' ) ) {
		return;
	}
	// Trust the logged in users.
	if ( is_user_logged_in() ) {
		return;
	}
	// Our timer field
	echo '<input type="hidden" name="secupress_dcts_timer" id="secupress_dcts_timer" value="' . time() . '" />';
}

add_action( 'pre_comment_on_post', 'secupress_fightspam_dont_comment_too_soon_check', 9 );
/**
 * Early block the comment if the timer is too short
 *
 * @author Julio Potier
 * @return void
 **/
function secupress_fightspam_dont_comment_too_soon_check() {
	// Do not do it if the setting is not set
	if ( ! secupress_get_module_option( 'antispam_comment-delay', 1, 'antispam' ) ) {
		return;
	}
	// Trust the logged in users.
	if ( is_user_logged_in() ) {
		return;
	}
	/**
	 * Filter the deffault timer, 30 by default
	 */
	$secupress_dcts_timer = (int) apply_filters( 'secupress.plugins.fightspam.comment_timer', 30 );
	// Bad timer? Bail!
	if ( $secupress_dcts_timer <= 0 ) {
		return;
	}
	// Timer is too short, block!
	if ( ! isset( $_POST['secupress_dcts_timer'] ) || ( time() - $_POST['secupress_dcts_timer'] ) < ( $secupress_dcts_timer + 1 ) ) { // +1sec because of page load + AJAX call.
		secupress_block( 'ATS', __( 'Sorry, you cannot send that now.', 'secupress' ) );
	}
}

add_action( 'wp_ajax_nopriv_secupress_dcts_timer', 'secupress_dcts_timer_cb' );
/**
 * Get a timer with AJAX
 *
 * @author Julio Potier
 * @since 2.3
 **/
function secupress_dcts_timer_cb() {
	// Do not do it if the setting is not set
	if ( ! secupress_get_module_option( 'antispam_comment-delay', 1, 'antispam' ) ) {
		return;
	}
	echo time();
	die();
}