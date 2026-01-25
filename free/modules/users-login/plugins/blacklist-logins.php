<?php
/**
 * Module Name: Disallowed Logins
 * Description: Forbid some usernames to be used.
 * Main Module: users_login
 * Author: SecuPress
 * Version: 2.3.19.1
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );

// EMERGENCY BYPASS!
if ( defined( 'SECUPRESS_ALLOW_LOGIN_ACCESS' ) && SECUPRESS_ALLOW_LOGIN_ACCESS ) {
	return;
}

add_action( 'admin_init', 'secupress_do_auth_redirect_early' );
/**
 * Force the auth_redirect on admin-post, admin-ajax, REST
 *
 * @since 2.3.19.1 Add secupress_ip_is_whitelisted()
 * @since 2.3.18
 * @author Julio Potier
 **/
function secupress_do_auth_redirect_early() {
	if ( secupress_ip_is_whitelisted() ) {
		return;
	} elseif ( is_user_logged_in() && ! secupress_is_soft_request() ) {
		auth_redirect();
	}
}


/** --------------------------------------------------------------------------------------------- */
/** EXISTING USERS WITH A BLACKLISTED USERNAME MUST CHANGE IT. ================================== */
/** --------------------------------------------------------------------------------------------- */

add_action( 'auth_redirect', 'secupress_auth_redirect_blacklist_logins', 11 );
/**
 * As soon as we are sure a user is connected, and before any redirection, check if the user login is not blacklisted.
 * If he is, he can't access the administration area and is asked to change it.
 *
 * @since 2.3.19 Use secupress_login_page() instead of secupress_action_page()
 * @since 1.0
 * @author Julio Potier
 *
 * @param (int) $user_id
 */
function secupress_auth_redirect_blacklist_logins( $user_id ) {
	global $sp_action, $wp_errors;

	if ( ! is_user_logged_in() ) {
		return;
	}

	$raw_user = get_userdata( $user_id );

	if ( ! secupress_is_username_blacklisted( $raw_user->user_login ) ) {
		// Good, the login is not blacklisted.
		return;
	}

	global $sp_action;
	$sp_action      = 'new-login';
	$post_param     = "secupress-blacklist-logins-{$sp_action}";
	$nonce_action   = "{$post_param}-{$user_id}";
	$error          = '';

	// A new login is submitted.
	if ( isset( $_POST[ $post_param ], $_POST['sp_action'] ) && $sp_action === $_POST['sp_action'] ) {
		$user_login = sanitize_user( $_POST[ $post_param ], true );

		if ( empty( $_POST['_wpnonce'] ) || ! wp_verify_nonce( $_POST['_wpnonce'], $nonce_action ) ) {
			secupress_die( __( 'Something went wrong.', 'secupress' ), '', [ 'force_die' => true, 'context' => 'bad_usernames_on_login', 'attack_type' => 'login' ] );
		}

		if ( empty( $user_login ) ) {
			// Empty username.
			$error = __( 'Username required', 'secupress' );
		} 
		// Sanitize the submitted username.
		if ( secupress_is_username_blacklisted( $user_login ) ) {
			// The new login is blacklisted.
			$error = __( 'Sorry, that username is not allowed.', 'secupress' );
		} else {
			// Good, change the user login.
			$inserted = secupress_blacklist_logins_change_user_login( $user_id, $user_login );
			if ( is_wp_error( $inserted ) ) {
				// Too bad, try again.
				$error = $inserted->get_error_message();
			} 
		} 

		if ( ! $error ) {
			// Use the new login now, to be included in the email
			$raw_user->user_login = $user_login;
			// Send the new login by email.
			secupress_blocklist_logins_new_user_notification( $raw_user );
			secupress_add_transient_notice( sprintf( _nx( 'Your %1$s has been updated as %2$s.', 'Your %1$s have been updated as %2$s.', 1, 'a nickname', 'secupress' ), __( 'username', 'secupress' ), secupress_tag_me( esc_html( $user_login ), 'strong' ) ), 'updated', 'username-updated', 'exist' );
			// Kill session.
			wp_clear_auth_cookie();
			wp_destroy_current_session();

			// Redirect the user to the login page.
			$redirect  = strpos( secupress_get_current_url( 'raw' ), wp_login_url() ) === false ? secupress_get_current_url( 'raw' ) : admin_url();
			$login_url = wp_login_url( $redirect, true );
			$login_url = add_query_arg( 'secupress-relog', $sp_action, $login_url );
			$login_url = add_query_arg( 'wp_lang', get_user_locale(), $login_url );
			wp_redirect( esc_url_raw( $login_url ) );
			die();
		}
	}

	$message   = sprintf(
		/* Translators: 1st is 'nickname/display name/public name/username' ; 2nd is the actual value in <strong> */
		_n( 'Your current %s %s is not allowed.', 'Your current %s %s are not allowed.', 1, 'secupress' ),
		__( 'username', 'secupress' ),
		secupress_tag_me( esc_html( $raw_user->user_login ), 'strong' )
	);
	$message  .= '<br>' . _n( 'You must update it to successfully log in.', 'You must update them to successfully log in.', 1, 'secupress' ); // 1 : one username

	$wp_errors = new WP_Error();
	$wp_errors->add( "{$sp_action}-message", $message, 'message' );
	if ( $error ) {
		$wp_errors->add( "{$sp_action}-error", $error, 'error' );
		add_action( 'secupress_login_page.shake_js', '__return_true' );
	}
	// The form.
	ob_start();
	?>
	<form name="loginform" id="loginform" action="" method="post">
		<p>
			<label for="<?php echo $sp_action; ?>"><?php _e( 'New username:', 'secupress' ); ?></label><br/>
			<input type="text" id="<?php echo $sp_action; ?>" name="<?php echo $post_param; ?>" value="" maxlength="60" required="required" aria-required="true" pattern="[A-Za-z0-9 _.\-@]{2,60}" autocorrect="off" autocapitalize="off" title="<?php echo esc_attr( secupress_blacklist_logins_allowed_characters() ); ?>"/>
		</p>
		<?php
		submit_button( _x( 'Rename', 'verb', 'secupress' ) );
		wp_nonce_field( $nonce_action );
		?>
		<input type="hidden" name="sp_action" value="<?php echo esc_attr( $sp_action ); ?>">
	</form>
	<?php
	$content = ob_get_contents();
	ob_end_clean();
	
	unset( $raw_user );

	if ( ! secupress_is_soft_request() ) {
		wp_send_json_error( [ 'error' => $error, 'message' => $message ] );
	} else {
		secupress_login_page( __( 'Please change your username', 'secupress' ), $content, $wp_errors );
	}
}


add_action( 'auth_redirect', 'secupress_pro_same_usernames_on_login', 12 );
/**
 * Check the login same as nickname/display_name on login
 *
 * @since 2.3.17
 * @author Julio Potier
 * 
 * @param (mixed) $raw_user
 * @param (string) $username
 * 
 * @return (mixed) $raw_user Can also display a form to ask a new strong password
 **/
function secupress_pro_same_usernames_on_login( $user_id ) {
	global $sp_action, $wp_errors;

	if ( ! secupress_get_module_option( 'blacklist-logins_lexicomatisation', 0, 'users-login' ) ) {
		return;
	}

	if ( ! is_user_logged_in() ) {
		return;
	}
	$raw_user = get_userdata( $user_id );
	$which    = secupress_pro_same_usernames_get_which( $raw_user );
	if ( is_a( $raw_user, 'WP_User' ) && ! empty( $which ) ) {
		if ( ! empty( trim( $raw_user->first_name ) ) || ! empty( trim( $raw_user->last_name ) ) ) {
			$new_name = trim( trim( $raw_user->first_name ) . ' ' . trim( $raw_user->last_name ) );
			if ( $new_name ) {
				if ( isset( $which['nickname'] ) ) {
					$raw_user->nickname     = $new_name;
				}
				if ( isset( $which['display_name'] ) ) {
					$raw_user->display_name = $new_name;
				}
				if ( isset( $which['nicename'] ) ) {
					$raw_user->user_nicename = sanitize_title( $new_name );
				}
				secupress_add_transient_notice( sprintf( _nx( 'Your %1$s has been updated as %2$s.', 'Your %1$s have been updated as %2$s.', count( $which ), 'a nickname', 'secupress' ), wp_sprintf_l( '%l', $which ), secupress_tag_me( esc_html( $new_name ), 'strong' ) ), 'updated', 'nickname-updated', 'exist' );
				wp_update_user( $raw_user );
			}
		} elseif ( isset( $which['nicename'] ) && $raw_user->user_nicename !== sanitize_title( $raw_user->display_name ) ) {
			$raw_user->user_nicename = sanitize_title( $raw_user->display_name );
			secupress_add_transient_notice( sprintf( _nx( 'Your %1$s has been updated as %2$s.', 'Your %1$s have been updated as %2$s.', 1, 'a nickname', 'secupress' ), wp_sprintf_l( '%l', $which ), secupress_tag_me( sanitize_title( $raw_user->display_name ), 'strong' ) ), 'updated', 'nickname-updated', 'exist' );
			wp_update_user( $raw_user );
		}
		$which = secupress_pro_same_usernames_get_which( $raw_user );
		if ( empty( $which ) ) {
			return;
		}
	} else {
		return;
	}

	global $sp_action;
	$sp_action      = 'new-names';
	$post_param     = "secupress-blacklist-logins-{$sp_action}";
	$nonce_action   = "{$post_param}-{$user_id}";
	$error          = '';
	$which          = secupress_pro_same_usernames_get_which( $raw_user );

	// A new name is submitted.
	if ( isset( $_POST['secupress-blacklist-logins-new-names'] ) ) {

		if ( empty( $_POST['_wpnonce'] ) || ! wp_verify_nonce( $_POST['_wpnonce'], $nonce_action ) ) {
			secupress_die( __( 'Something went wrong.', 'secupress' ), '', [ 'force_die' => true, 'context' => 'same_usernames_on_login', 'attack_type' => 'login' ] );
		}
		$new_name = trim( $_POST['secupress-blacklist-logins-new-names'] );
		if ( empty( $new_name ) ) {
			$error = __( 'Name required.', 'secupress' );
		}
		if ( 0 === strcmp( $new_name, $raw_user->user_login ) ) {
			$error = __( 'Sorry, this should be different from your login.', 'secupress' );
		}
		if ( secupress_get_user_by( $new_name ) ) {
			$error = __( 'Sorry, that username already exists!', 'secupress' );
		}
		if ( ! $error ) {
			if ( isset( $which['nickname'] ) ) {
				$raw_user->nickname     = $new_name;
			}
			if ( isset( $which['display_name'] ) ) {
				$raw_user->display_name = $new_name;
			}
			// Check if the sanitized nicename is already in use, if true, make it unique.
			if ( isset( $which['nicename'] ) ) {
				$def_user_nicename       = sanitize_title( $raw_user->user_login );
				$raw_user->user_nicename = sanitize_title( $new_name, $def_user_nicename );
			}
			$i = 0;
			while ( secupress_get_user_by( $raw_user->user_nicename . ( $i ? "-{$i}" : '' ) ) ) {
				++$i;
			}
			if ( $i ) {
				$raw_user->user_nicename = $raw_user->user_nicename . "-{$i}";
			}
			$last = '';
			if ( $i ) {
				unset( $which['nicename'] );
				$last = ' ' . sprintf( __( 'Your author profil URL slug has to be updated as %s.', 'secupress' ), secupress_tag_me( esc_html( $raw_user->user_nicename ), 'strong' ) );
			}
			secupress_add_transient_notice( sprintf( _nx( 'Your %1$s has been updated as %2$s.', 'Your %1$s have been updated as %2$s.', count( $which ), 'a nickname', 'secupress' ), wp_sprintf_l( '%l', $which ), secupress_tag_me( esc_html( $new_name ), 'strong' ) ) . $last, 'updated', 'nickname-updated', 'exist' );

			wp_update_user( $raw_user );
			return;
		}
	}
	$whiches  = wp_sprintf_l( '%l', $which );

	$message  = sprintf(
		/* Translators: 1st is 'nickname/display name/public name/username' ; 2nd is the actual value in <strong> */
		_n( 'Your current %s %s is not allowed.', 'Your current %s %s are not allowed.', count( $which ), 'secupress' ),
		$whiches,
		'(' . secupress_tag_me( esc_html( $raw_user->user_login ), 'strong' ) . ')',
	);
	$message .= '<br>' . _n( 'You must update it to successfully log in.', 'You must update them to successfully log in.', count( $which ), 'secupress' ); // 1 : one password

	$wp_errors = new WP_Error();
	$wp_errors->add( "{$sp_action}-message", $message, 'message' );
	if ( $error ) {
		// $error .= '<br>' . __( 'Find one that is not the same as your username', 'secupress' );
		$wp_errors->add( "{$sp_action}-error", $error, 'error' );
		add_action( 'secupress_login_page.shake_js', '__return_true' );
	}
	ob_start();
	?>
	<form name="loginform" id="loginform" action="" method="post">
		<p>
			<label for="secupress-blacklist-logins-new-names">
			<?php
			printf( '%s %s.', sprintf( __( '%s:', 'secupress' ), _x( 'Rename', 'verb', 'secupress' ) ), $whiches );
			?>
			</label><br/>
			<input type="text" name="secupress-blacklist-logins-new-names" id="secupress-blacklist-logins-new-names" class="regular-text" value="" autocomplete="off" />
		</p>
		<?php
		wp_nonce_field( $nonce_action );
		submit_button( _x( 'Rename', 'verb', 'secupress' ) );
		?>
	</form>
	<?php
	unset( $raw_user );
	$content = ob_get_contents();
	ob_end_clean();
	unset( $raw_user );
	if ( ! secupress_is_soft_request() ) {
		wp_send_json_error( [ 'error' => $error, 'message' => $message ] );
	} else {
		secupress_login_page( __( 'Please update your profil names', 'secupress' ), $content, $wp_errors );
	}
}


/** --------------------------------------------------------------------------------------------- */
/** UTILITIES =================================================================================== */
/** --------------------------------------------------------------------------------------------- */

/**
 * Change a user login.
 *
 * @since 1.0
 * @author Julio Potier
 *
 * @param (int)    $user_id    I let you guess what it is.
 * @param (string) $user_login Well...
 *
 * @return (int|object) User ID or WP_Error object on failure.
 */
function secupress_blacklist_logins_change_user_login( $user_id, $user_login ) {
	global $wpdb;

	// `user_login` must be between 1 and 60 characters.
	if ( empty( $user_login ) ) {
		return new WP_Error( 'empty_user_login', __( 'Cannot create a user with an empty login name.' ) );
	} elseif ( mb_strlen( $user_login ) > 60 ) {
		return new WP_Error( 'user_login_too_long', __( 'Username may not be longer than 60 characters.' ) );
	}

	if ( username_exists( $user_login ) ) {
		return new WP_Error( 'existing_user_login', __( 'Sorry, that username already exists!' ) );
	}

	$wpdb->update( $wpdb->users, array( 'user_login' => $user_login ), array( 'ID' => $user_id ) );

	wp_cache_delete( $user_id, 'users' );
	wp_cache_delete( $user_login, 'userlogins' );

	secupress_scanit( 'Bad_Usernames' );

	return $user_id;
}


/**
 * Send an email notification to a user with his/her login.
 *
 * @since 1.0
 * @author Julio Potier
 *
 * @param (int|object) $user A user ID or a user object.
 */
function secupress_blocklist_logins_new_user_notification( $user ) {
	$user     = secupress_is_user( $user ) ? $user : get_userdata( $user );
	/* Translators: 1 is a blog name. */
	$subject  = sprintf( __( '[%s] Your username info', 'secupress' ), '###SITENAME###' );
	$message  = sprintf( __( 'Username: %s', 'secupress' ), $user->user_login ) . "\r\n\r\n";
	$message .= esc_url_raw( wp_login_url() ) . "\r\n";

	/**
	 * Filter the mail subject
	 * @param (string) $subject
	 * @param (WP_User) $user
	 * @since 2.2
	 */
	$subject = apply_filters( 'secupress.mail.blocklist_logins.subject', $subject, $user );
	/**
	 * Filter the mail message
	 * @param (string) $message
	 * @param (WP_User) $user
	 * @since 2.2
	 */
	$message = apply_filters( 'secupress.mail.blocklist_logins.message', $message, $user );

	secupress_send_mail( $user->user_email, $subject, $message );
}


/**
 * Tell if a username is blacklisted.
 *
 * @since 2.2.6 stripos( $username, 'admin' )
 * @author Julio Potier
 * 
 * @since 1.0
 * @author Grégory Viguier
 *
 * @param (string) $username The username to test.
 *
 * @return (bool) true if blacklisted.
 */
function secupress_is_username_blacklisted( $username ) {
	if ( secupress_get_module_option( 'blacklist-logins_admin', 0, 'users-login' ) && stripos( $username, 'admin' ) !== false && strtolower( $username ) !== 'admin' ) {
		return ! isset( apply_filters( 'secupress.plugins.allowed_usernames', [] )[ $username ] );
	}
    $list           = secupress_get_blacklisted_usernames();
    $list_flipped   = array_flip( $list );
    $username_lower = mb_strtolower( $username );

    // Cgeck for exact match
    if ( isset( $list_flipped[ $username_lower ] ) ) {
        return true;
    }

    // Or check for match from start
    foreach ( $list as $blacklisted_name ) {
        $blacklisted_name_replaced = str_replace( '*', '', $blacklisted_name );
        if ( strpos( $blacklisted_name, '*' ) > 0 && ( strpos( $username_lower, mb_strtolower( $blacklisted_name_replaced ) ) === 0 || isset( $list_flipped[ $blacklisted_name_replaced ] ) ) ) { // 0 = first char. // * = only these names have to be checked like that
            return true;
        }
    }

    return false;
}


/**
 * Logins blacklist: return the list of allowed characters for the usernames.
 *
 * @since 1.0
 * @author Julio Potier
 *
 * @param (bool) $wrap If set to true, the characters will be wrapped with `code` tags.
 *
 * @return (string)
 */
function secupress_blacklist_logins_allowed_characters( $wrap = false ) {
	$allowed = is_multisite() ? array( 'a-z', '0-9' ) : array( 'A-Z', 'a-z', '0-9', '(space)', '_', '.', '-', '@' );
	if ( $wrap ) {
		foreach ( $allowed as $i => $char ) {
			$allowed[ $i ] = '<code>' . $char . '</code>';
		}
	}
	$allowed = wp_sprintf_l( '%l', $allowed );

	return sprintf( __( 'Allowed characters: %s.', 'secupress' ), $allowed );
}


/** --------------------------------------------------------------------------------------------- */
/** FORBID USER CREATION AND EDITION IF THE USERNAME IS BLACKLISTED. ============================ */
/** --------------------------------------------------------------------------------------------- */


add_filter( 'illegal_user_logins', 'secupress_blacklist_logins_illegal_user_logins' );
/**
 * Filter the blacklisted user names.
 * This filter is used in `wp_insert_user()`, `edit_user()` and `wpmu_validate_user_signup()`.
 *
 * @since 2.2.6 usage of 'illegal_user_logins' filter (compat 4.4), finally!
 * @since 1.0
 * @author Julio Potier
 *
 * @param (array) $usernames A list of forbidden user names.
 *
 * @return (array) The forbidden user names.
 */
function secupress_blacklist_logins_illegal_user_logins( $usernames ) {
	return array_merge( $usernames, secupress_get_blacklisted_usernames() );
}


add_action( 'user_profile_update_errors', 'secupress_blacklist_logins_user_profile_update_errors', 10, 3 );
/**
 * In `edit_user()`, detect forbidden logins.
 *
 * @since 1.0
 * @author Julio Potier
 *
 * @param (object) $errors A WP_Error object, passed by reference.
 * @param (bool)   $update Whether this is a user update.
 * @param (object) $user   A WP_User object, passed by reference.
 *
 * @return (object) The WP_Error object with a new error if the user name is blacklisted.
 */
function secupress_blacklist_logins_user_profile_update_errors( $errors, $update, $user ) {
	if ( secupress_is_username_blacklisted( $user->user_login ) ) {
		$errors->add( 'user_name',  __( 'Sorry, that username is not allowed.', 'secupress' ) );
	}
	return $errors;
}


add_filter( 'wpmu_validate_user_signup', 'secupress_blacklist_logins_wpmu_validate_user_signup' );
/**
 * In `wpmu_validate_user_signup()`, detect forbidden logins.
 *
 * @since 1.0
 * @author Julio Potier
 *
 * @param (array) $result An array containing the sanitized user name, the original one, the user email, and a `WP_Error` object.
 *
 * @return (array) The array with a new error if the user name is blacklisted.
 */
function secupress_blacklist_logins_wpmu_validate_user_signup( $result ) {
	if ( secupress_is_username_blacklisted( $result['user_name'] ) ) {
		$result['errors']->add( 'user_name',  __( 'Sorry, that username is not allowed.', 'secupress' ) );
	}
	return $result;
}

add_action( 'secupress.modules.activate_submodule_' . basename( __FILE__, '.php' ), 'secupress_bad_logins_de_activate_file' );
add_action( 'secupress.modules.deactivate_submodule_' . basename( __FILE__, '.php' ), 'secupress_bad_logins_de_activate_file' );
/**
 * On module de/activation, rescan.
 * @author Julio Potier
 * @since 2.0
 */
function secupress_bad_logins_de_activate_file() {
	secupress_scanit( 'Bad_Usernames' );
}

add_filter( 'user_row_actions', 'secupress_bad_logins_css', 10, 2 );
function secupress_bad_logins_css( $dummy, $user_object ) {
	static $even;
	$even++;
	if ( secupress_is_username_blacklisted( $user_object->user_login ) ) {
		$bg = $even % 2 !== 0 ? "background-image: linear-gradient(130deg, rgba(170, 170, 170, 0.07) 25%, transparent 25%, transparent 50%, rgba(170, 170, 170, 0.07) 50%, rgba(170, 170, 170, 0.07) 75%, transparent 75%, transparent 100%);"
						: "background-image: linear-gradient(130deg, rgba(170, 170, 170, 0.13) 25%, transparent 25%, transparent 50%, rgba(170, 170, 170, 0.13) 50%, rgba(170, 170, 170, 0.13) 75%, transparent 75%, transparent 100%);";
        echo "<style type='text/css'>
            #user-{$user_object->ID} {
        		{$bg}
                background-size: 12px 15px;
            }
        </style>";
	}
	return $dummy;
}

add_filter( 'views_users', 'secupress_bad_username_view' );
/**
 * Add the "Bad username" tab to the users.php page.
 *
 * @since 2.2.6
 * @author Julio Potier
 *
 * @param array $views An array of user views.
 * @return array Modified array of user views.
 */
function secupress_bad_username_view( $views ) {
    $bad_usernames = count( secupress_get_bad_username_ids() );
    if ( ! $bad_usernames ) {
    	return $views;
    }
    $current             = isset( $_GET['secupress_bad_username'] );
    if ( $current ) {
    	$views['all']    = str_replace( 'class="current"', '', $views['all'] );
    }

    $views['secupress_bad_username'] = sprintf(
        '<a href="%s"%s>%s <span class="count">(%s)</span></a>',
        esc_url( add_query_arg( 'secupress_bad_username', 1, admin_url( 'users.php' ) ) ),
        $current ? ' class="current"' : '',
        __( 'Bad Username', 'secupress' ),
        $bad_usernames
    );

    return $views;
}


/**
 * Get IDs of the bad username users
 *
 * @since 2.2.6
 * @author Julio Potier
 * 
 * @return (array) $user_ids The IDs of the bad username users
 **/
function secupress_get_bad_username_ids() {
    global $wpdb;
    static $user_ids;

	if ( ! empty( $user_ids ) ) {
		return $user_ids;
	} 
    $like = '';
    $list = secupress_get_blacklisted_usernames();
    $jokr = array_filter( $list , function( $a ){ return false !== strpos( $a, '*' ); } );
    $list = array_filter( $list , function( $a ){ return false === strpos( $a, '*' ); } );
    $list = implode( '\',\'', $list );
    if ( ! empty( $jokr ) ) {
		$like .= ' OR ' . implode( ' OR ', array_map( function( $username ) {
		return "user_login LIKE '" . str_replace( '*', '%', $username ) . "'";
		}, $jokr ) );    	
    }
	if ( secupress_get_module_option( 'blacklist-logins_admin', 0, 'users-login' ) ) {
		$like .= " OR ( user_login LIKE '%admin%' AND user_login != 'admin')";
	}
	$allowed_usernames = array_flip( apply_filters( 'secupress.plugins.allowed_usernames', [] ) );
	if ( ! empty( $allowed_usernames ) ) {
		$like .= ' AND (' . implode( ' OR ', array_map( function( $username ) {
		return "user_login NOT LIKE '" . str_replace( '*', '%', $username ) . "'";
		}, $allowed_usernames ) ) . ')';    	
	}
    // No sanitization needed since it's hardcoded, no user input.
    $sql      = "SELECT ID FROM {$wpdb->users} WHERE user_login in ('{$list}')" . $like;
    $user_ids = $wpdb->get_col( $sql );

    return $user_ids;
}

add_action( 'pre_get_users', 'secupress_bad_username_custom_modify_user_query' );
/**
 * Modify the user query based on the "Connected users" filter.
 *
 * @since 2.2.6
 * @author Julio Potier
 *
 * @param WP_User_Query $query The WP_User_Query instance.
 * @return WP_User_Query Modified WP_User_Query instance.
 */
function secupress_bad_username_custom_modify_user_query( $query ) {
	global $pagenow;
	if ( ! isset( $pagenow ) || 'users.php' !== $pagenow || ! is_admin() ) {
		return $query;
	}
	$_user_ids = [];
	remove_action( 'pre_get_users', 'secupress_bad_username_custom_modify_user_query' );
	if ( isset( $_GET['secupress_bad_username'] ) && $_GET['secupress_bad_username'] === '1' ) {
		$_user_ids = secupress_get_bad_username_ids();
	}
	add_action( 'pre_get_users', 'secupress_bad_username_custom_modify_user_query' );

	if ( ! empty( $_user_ids ) ) {
		$query->set( 'include', $_user_ids );
	}
	return $query;
}

add_filter( 'body_class', 'secupress_usernames_security_body_class', 100 );
/**
  * Filter body_class in order to hide User ID and User nicename
  * 
  * @since 2.2.6
  * @author Roch Daniel, Julio Potier
  * 
  * @param (array) $classes
  * 
  * @return (array)
  */
function secupress_usernames_security_body_class( $classes ) {
	if ( is_author() ) {
		$current_auth = get_query_var( 'author_name' ) ? get_user_by( 'slug', get_query_var( 'author_name' ) ) : get_userdata( get_query_var( 'author' ) );
		$disallowed   = [];
		$disallowed[] = 'author-' . $current_auth->ID;
		$disallowed[] = 'author-' . $current_auth->user_nicename;
		$classes      = array_diff( $classes, $disallowed );
	}
	return $classes;
}

add_action( 'admin_init', 'secupress_lexicomatisation_set_expert' );
/**
 * Add our module to the global
 *
 * @since 2.3.17
 * @author Julio Potier
 **/
function secupress_lexicomatisation_set_expert() {
	if ( ! secupress_get_module_option( 'blacklist-logins_lexicomatisation', 0, 'users-login' ) ) {
		return;
	}
	$GLOBALS['SECUPRESS_EXPERT_MODULES_ON']['lexicomatisation'] = true;
}

add_action( 'personal_options_update',  'secupress_usernames_security_name_filter' );
add_action( 'edit_user_profile_update', 'secupress_usernames_security_name_filter' );
/**
 * Save the user names and display error notices.
 *
 * @since 2.3.18.1
 * @author Julio Potier
 */
function secupress_usernames_security_name_filter() {
	if ( ! secupress_get_module_option( 'blacklist-logins_lexicomatisation', 0, 'users-login' ) ) {
		return;
	}
	if ( empty( $_POST['user_id'] ) ) {
		return;
	}

	$user_id = (int) $_POST['user_id'];
	$error   = '';

	check_admin_referer( 'update-user_' . $user_id );

	if ( ! ( $userdata = get_userdata( $user_id ) ) ) {
		return;
	}

	if ( isset( $_POST['nickname'] ) && $_POST['nickname'] === $userdata->user_login ) {
		$error = _x( 'Nickname', 'bad logins', 'secupress' );
	}
	if ( isset( $_POST['display_name'] ) && $_POST['display_name'] === $userdata->user_login ) {
		$error = _x( 'Display Name', 'bad logins', 'secupress' );
	}
	if ( isset( $_POST['user_nicename'] ) && $_POST['user_nicename'] === $userdata->user_login ) {
		$error = _x( 'Nicename', 'bad logins', 'secupress' );
	}
	if ( $error ) {
		$error = sprintf( __( '<strong>Error</strong>: A %s different from the login is required.', 'secupress' ), $error );
		add_action( 'user_profile_update_errors', function( $errors ) use ( $error ) {
			$errors->add( 'user_name', $error );
		} );
	}
}

/**
  * Return the needed public names identical to the user's login
  * 
  * @since 2.3.17
  * @author Julio Potier
  * 
  * @param (WP_User) $user
  * 
  * @return (array)
  */
function secupress_pro_same_usernames_get_which( $user ) {
	if ( ! is_a( $user, 'WP_User' ) ) {
		return [];
	}

	$result = [];

	if ( 0 === strcmp( $user->user_login, $user->nickname ) ) {
		$result['nickname']     = _x( 'Nickname', 'bad logins', 'secupress' );
	}
	if ( 0 === strcmp( $user->user_login, $user->display_name ) ) {
		$result['display_name'] = _x( 'Display Name', 'bad logins', 'secupress' );
	}
	if ( 0 === strcmp( $user->user_login, $user->user_nicename ) ) {
		$result['nicename']     = _x( 'Author Profile URL', 'bad logins', 'secupress' );
	}
	
	return $result;
}
