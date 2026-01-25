<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/**
 * Get the Disallowed usernames.
 *
 * @author Julio Potier
 * @since 2.2.6
 * @author Grégory Viguier
 * @since 1.0
 *
 * @return (array)
 */
function secupress_get_blacklisted_usernames() {
	// Disallowed usernames.
	// usernames with "*" are basically from malwares where the joker "*" is a random number
	$filename = secupress_get_data_file_path( 'disallowed_logins_list' );
	$list     = [];
	if ( $filename ) {
		$list = explode( ',', file_get_contents( $filename ) );
	}
	/**
	 * Filter the list of Disallowed usernames.
	 *
	 * @since 2.0
	 *
	 * @param (array) $list List of usernames.
	 */
	$list = apply_filters( 'secupress.plugin.disallowed_logins_list', $list );
	if ( has_filter( 'secupress.plugin.disallowed_logins_list' ) ) {
   		_deprecated_hook( 'secupress.plugin.disallowed_logins_list', '2.2.6', 'secupress.plugins.disallowed_logins_list' );
	}
	$list = apply_filters( 'secupress.plugins.disallowed_logins_list', $list );

	// Temporarily allow some Disallowed usernames.
	$allowed = (array) secupress_cache_data( 'allowed_usernames' );
	if ( $allowed ) {
		$list = array_diff( $list, $allowed );
		secupress_cache_data( 'allowed_usernames', array() );
	}

	return $list;
}

/**
 * Return an array of forbidden roles
 *
 * @since 2.0
 * @author Julio Potier
 *
 * @see roles_radios
 *
 * @return (array) $roles
 **/
function secupress_get_forbidden_default_roles() {
	$roles = [ 'administrator' => true ];
	$roles = apply_filters( 'secupress.plugin.default_role.forbidden', $roles );
	if ( has_filter( 'secupress.plugin.default_role.forbidden' ) ) {
		_deprecated_hook( 'secupress.plugin.default_role.forbidden', '2.2.6', 'secupress.plugins.default_role.forbidden' );
	}
	/**
	* Filter the forbidden roles
	* @param (array) $roles, format 'role' => true
	*/
	$roles = apply_filters( 'secupress.plugins.default_role.forbidden', $roles );

	return $roles;
}


/**
 * Return the distance between 2 strings from 0 (same) to 1 (different)
 *
 * @since 2.2.6
 * @author Julio Potier
 *
 * @param (string) $str1 The first string to compare
 * @param (string) $str2 The second string to compare
 *
 * @return (float)
 **/
function secupress_levenshtein( $str1, $str2 ) {
    $distance = levenshtein( $str1, $str2 );
    $maxlen   = max( strlen( $str1 ), strlen( $str2 ) );
    return 1 - ( $distance / $maxlen );
}

/**
 * Detect if the user has a mobile session
 *
 * @author Julio Potier
 * @since 2.2.6
 * 
 * @param (int)   $user_id
 * @return (bool) True if the user_id has at least one mobile session
 **/
function secupress_user_has_mobile_session( $user_id ) {
	$sessions_inst = WP_Session_Tokens::get_instance( $user_id );
	$all_sessions  = $sessions_inst->get_all();
	if ( empty( $all_sessions ) ) {
		return false;
	}
	return (bool) count( array_filter( wp_list_pluck( $all_sessions, 'ua' ), 'secupress_is_mobile' ) );
}

/**
 * Get the roles of a user.
 * 
 * @author Julio Potier
 * @since 2.2.6
 * 
 * @param int $user_id The user ID.
 * @return array The user roles.
 */
function secupress_get_user_roles( $user_id ) {
	$user = get_user_by( 'ID', $user_id );

	return isset( $user->roles ) ? $user->roles : [];
}

/**
 * Get user IDs with active sessions.
 *
 * @since 2.2.6
 * @author Julio Potier
 *
 * @return (array) User IDs with active sessions.
 */
function secupress_get_connected_user_ids() {
	static $user_ids = [];
	$user_ids = $user_ids ?? [];

	if ( ! empty( $user_ids ) ) {
		return $user_ids;
	}

	// Get all user IDs
	$users = get_users( [
		'meta_key'     => 'session_tokens',
		'meta_compare' => 'EXISTS'
	] );

	foreach ($users as $user) {
		$instance = WP_Session_Tokens::get_instance( $user->ID );
		$sessions = $instance->get_all();
		foreach ( $sessions as $session ) {
			if ( $session['expiration'] > time() ) {
				$user_ids[] = $user->ID;
				break; // No need to check further tokens for this user
			}
		}
	}

	return $user_ids;
}

/**
 * Check if a user is a fake user.
 *
 * @author Julio Potier
 * @since 2.2.6
 * 
 * @param int $user_id The user ID.
 * @return (string|bool) Descriptive word if the user is a fake user, false otherwise.
 */
function secupress_is_fake_user( $user_id ) {
	$_user = new WP_User( $user_id );

	if ( ! $_user->exists() ) {
		return 'not_exists';
	}

	if ( 32 >= strlen( $_user->user_pass ) ) {
		return 'wrong_passwordhash';
	}

	if ( '0000-00-00 00:00:00' === $_user->user_registered ) {
		return 'no_date';
	}

	if ( empty( $_user->user_nicename ) ) {
		return 'no_nicename';
	}

	$_meta = get_user_meta( $user_id, SECUPRESS_USER_PROTECTION, true );
	if ( ! $_meta ) {
		return 'no_metadata';
	}

	$modulo = secupress_get_option( 'secupress_user_protection_modulo' );
	$seed   = secupress_get_option( 'secupress_user_protection_seed' );

	if ( $_meta != ( $user_id * $seed ) % $modulo ) { // do not use !==, do not cast $_meta as int to do so.
		return 'no_modulo';
	}

	if ( ! is_email( $_user->user_email ) ) {
		return 'wrong_email_dom';
	}

	if ( secupress_is_submodule_active( 'users-login', 'same-email-domain' ) && secupress_email_domain_is_same( $_user->user_email ) ) {
		return 'same_email';
	}

	if ( secupress_is_submodule_active( 'users-login', 'bad-email-domains' ) ) {
		// special cache system here, this cost a lot and takes a long time to check.
		if ( get_user_meta( $_user->ID, 'secupress-bad-mx-' . md5( $_user->user_email ), true ) ) {
			return 'wrong_email_mx';
		} else if ( secupress_pro_bad_email_domain_is_bad( $_user->user_email ) ) {
			update_user_meta( $_user->ID, 'secupress-bad-mx-' . md5( $_user->user_email ), 1 );
			return 'wrong_email_mx';
		}
	}

	$admins = get_option( SECUPRESS_ADMIN_IDS );
	if ( $admins && user_can( $_user, 'administrator' ) && ! in_array( $user_id, $admins ) ) {
		return 'not_admin';
	}

	return false; // This is a correct user
}

/**
 * Get the fake users
 *
 * @author Julio Potier
 * @since 2.2.6
 * 
 * @return array The fake users.
 */
function secupress_get_fake_users() {
	global $wpdb;
	static $fake_users;

	if ( isset( $fake_users ) ) {
		return $fake_users;
	}

	$temp_users = [];
	$fake_users = [];

	if ( class_exists( 'SecuPress_User_Protection' ) ) {
	    remove_action( 'pre_get_users', array( $GLOBALS['SecuPress_User_Protection'], 'filter_fake_users' ) );
	}
	// #1 Get fake users without metadata
	$modulo = secupress_get_option( 'secupress_user_protection_modulo' );
	$seed   = secupress_get_option( 'secupress_user_protection_seed' );

	// #2 Get fake users with wrong metadata
	$temp_users = $wpdb->prepare("
		SELECT u.ID
		FROM {$wpdb->users} AS u
		LEFT JOIN {$wpdb->usermeta} AS um ON u.ID = um.user_id AND um.meta_key = %s
		WHERE um.meta_key IS NULL OR um.meta_value != (u.ID * %d) %% %d;
	", SECUPRESS_USER_PROTECTION, $seed, $modulo);
	$temp_users = $wpdb->get_col( $temp_users );
	$fake_users = array_merge( $temp_users, $fake_users );

	// #3 Get fake users with a 0000-00-00 00:00:00 registered date
	$temp_users = $wpdb->get_col(
		"SELECT ID FROM {$wpdb->users} WHERE user_registered = '0000-00-00 00:00:00'",
	);
	$fake_users = array_merge( $temp_users, $fake_users );

	// #4 Get fake users with a 32-character password length
	$temp_users = $wpdb->get_col( "SELECT ID FROM {$wpdb->users} WHERE LENGTH(user_pass) <= 32" ); // md5 length, do not change
	$fake_users = array_merge( $temp_users, $fake_users );

	// #5 Get fake users with no nicename
	$temp_users = $wpdb->get_col(
		"SELECT ID FROM {$wpdb->users} WHERE LENGTH(user_nicename) = 0",
	);
	$fake_users = array_merge( $temp_users, $fake_users );

	// #6 Get users with bad domains MX
	if ( secupress_is_submodule_active( 'users-login', 'bad-email-domains' ) ) {
		$domain_conditions = implode( '|', secupress_pro_bad_email_domain_get_bad_tld_for_email() );
		$temp_users = $wpdb->get_col( $wpdb->prepare( "SELECT ID FROM $wpdb->users WHERE user_email REGEXP CONCAT('.(', %s, ')$')", $domain_conditions ) );
		$fake_users = array_merge( $temp_users, $fake_users );
	}

	// #7 Get users with same domain name
	if ( secupress_is_submodule_active( 'users-login', 'same-email-domain' ) ) {
		$website_domain = secupress_get_current_url( 'domain' );
		$temp_users     = $wpdb->get_col( $wpdb->prepare(
			 "SELECT ID FROM {$wpdb->users} WHERE user_email LIKE %s", '%' . $wpdb->esc_like( $website_domain )
			)
		);
		$fake_users = array_merge( $temp_users, $fake_users );
	}

	// #8 Get fake users with wrong email address
	$temp_users = $wpdb->get_col(
		"SELECT ID FROM {$wpdb->users} WHERE user_email NOT LIKE '%_@_%.__%'" // very basic but will works for the malwares, not for real case, do not use this for real verification.
	);
	$fake_users = array_merge( $temp_users, $fake_users );

	// #9 Get admin users granted directly in DB (not in SECUPRESS_ADMIN_IDS option)
	$_tmp_pends = secupress_get_pending_user_ids();
	$temp_users = get_users( [ 'role' => 'administrator', 'exclude' => array_merge( $_tmp_pends, get_option( SECUPRESS_ADMIN_IDS, [] ) ), 'number' => -1, 'fields' => 'ids' ] );
	$fake_users = array_merge( $temp_users, $fake_users );

	$fake_users = array_unique( $fake_users );
	
	// Convert IDs to user objects using our custom function that handles empty user_nicename
	$fake_users = array_map( function( $user_id ) {
		if ( ! $user_id ) {
			return null;
		}
		// Use secupress_get_user_by() which handles empty user_nicename gracefully
		$user = secupress_get_user_by( $user_id );
		return $user ? $user : null;
	}, $fake_users );
	
	// Remove null values (invalid users) and re-index array
	$fake_users = array_filter( $fake_users );
	$fake_users = array_values( $fake_users );

	if ( class_exists( 'SecuPress_User_Protection' ) ) {
		add_action( 'pre_get_users', array( $GLOBALS['SecuPress_User_Protection'], 'filter_fake_users' ) );
	}
	return $fake_users;
}

/**
 * Returns pending users (user_status=2) from custom query to prevent any filter
 *
 * @since 2.2.6
 * @author Julio Potier
 * 
 * @return (array)
 */
function secupress_get_pending_user_ids() { // do not add this in the class, we need it outside in secupress_get_fake_users()
	global $wpdb;
	static $ids;

	if ( isset( $ids ) ) {
		return $ids;
	}

	$query = "SELECT ID FROM $wpdb->users WHERE user_status = 2";
	$ids   = $wpdb->get_col( $query );

	return $ids;
}

/**
 * Returns true if the wp_users table contains any duplicated user_pass (which is 100% malicious)
 *
 * @author Julio Potier
 * @since 2.2.6
 * 
 * @return (bool)
 **/
function secupress_users_contains_duplicated_hashes() {
	global $wpdb;
	static $res;

	if ( isset( $res ) ) {
		return $res;
	}

	$query = "SELECT CASE WHEN count(distinct user_pass) = count(id) THEN 'false' ELSE 'true' END FROM $wpdb->users";
	$res   = $wpdb->get_var( $query ) === 'true';

	return $res;
}

/**
 * Returns administrators from custom query to prevent any filter
 *
 * @author Julio Potier
 * @since 2.2.6
 * 
 * @return (array)
 **/
function secupress_get_admin_ids_by_capa() {
	global $wpdb;
	static $ids;

	if ( isset( $ids ) ) {
		return $ids;
	}
	$query = "SELECT ID FROM $wpdb->users u INNER JOIN $wpdb->usermeta um ON u.ID = um.user_id WHERE um.meta_key LIKE '{$wpdb->prefix}capabilities' AND ( um.meta_value LIKE '%\"administrator\"%' OR um.meta_value LIKE '%\'administrator\'%');";
	$ids   = $wpdb->get_col( $query );

	return $ids;
}

/**
 * Check if the email has the same domain as this website
 *
 * @since 2.2.6
 * @author Julio Potier
 * 
 * @param (string) $email
 * @return (bool)
 **/
function secupress_email_domain_is_same( $email ) {
	static $website_domain;

	$domain  = substr( strrchr( $email, '@' ), 1 );

	// Check if the user email domain matches the website domain
	if ( ! isset( $website_domain ) ) {
		$website_domain = secupress_get_current_url( 'domain' );
	}
	if ( strcasecmp( $domain, $website_domain ) === 0 ) {
		return true;
	}

	return false;
}

/**
 * Select an emoji set for the captcha module
 *
 * @since 2.2.6
 * @author Julio Potier
 * 
 * @param (string) $set 'all' means return everything, 'random' means anything, or a key from $sets
 * 
 * @return (array) $sets
 **/
function secupress_get_emojiset( $set = 'random' ) {
	$sets              = [];

	$sets['numbers']   = [ '1️⃣' => _x( 'One', 'emoji', 'secupress' ),   '2️⃣' => _x( 'Two', 'emoji', 'secupress' ),    '3️⃣' => _x( 'Three', 'emoji', 'secupress' ),  '4️⃣' => _x( 'Four', 'emoji', 'secupress' ),    '5️⃣' => _x( 'Five', 'emoji', 'secupress' )   ];
	$sets['maths']     = [ '➕' => _x( 'Plus', 'emoji', 'secupress' ),  '➖' => _x( 'Minus', 'emoji', 'secupress' ),  '✖️' => _x( 'Times', 'emoji', 'secupress' ),  '➗' => _x( 'Divided', 'emoji', 'secupress' ), '🟰' => _x( 'Equal', 'emoji', 'secupress' )  ];
	$sets['game']      = [ '♠️' => _x( 'Spade', 'emoji', 'secupress' ), '♣️' => _x( 'Clover', 'emoji', 'secupress' ), '♥️' => _x( 'Heart', 'emoji', 'secupress' ),  '♦️' => _x( 'Diamond', 'emoji', 'secupress' ), '◼️' => _x( 'Square', 'emoji', 'secupress' ) ];
	$sets['animals']   = [ '🐶' => _x( 'Dog', 'emoji', 'secupress' ),   '🐱' => _x( 'Cat', 'emoji', 'secupress' ),    '🐵' => _x( 'Monkey', 'emoji', 'secupress' ), '🐷' => _x( 'Pig', 'emoji', 'secupress' ),     '🦁' => _x( 'Lion', 'emoji', 'secupress' )   ];
	$sets['nature']    = [ '🌳' => _x( 'Tree', 'emoji', 'secupress' ),  '🪵' => _x( 'Logs', 'emoji', 'secupress' ),   '🍀' => _x( 'Clover', 'emoji', 'secupress' ), '🍁' => _x( 'Leaf', 'emoji', 'secupress' ),    '🌸' => _x( 'Flower', 'emoji', 'secupress' ) ];
	$sets['fruits']    = [ '🍎' => _x( 'Apple', 'emoji', 'secupress' ), '🍌' => _x( 'Banana', 'emoji', 'secupress' ), '🍋' => _x( 'Lemon', 'emoji', 'secupress' ),  '🍇' => _x( 'Grapes', 'emoji', 'secupress' ),  '🥝' => _x( 'Kiwi', 'emoji', 'secupress' )   ];
	$sets['vegeta']    = [ '🌶️' => _x( 'Chili', 'emoji', 'secupress' ), '🥕' => _x( 'Carrot', 'emoji', 'secupress' ), '🌽' => _x( 'Corn', 'emoji', 'secupress' ),   '🥑' => _x( 'Avocado', 'emoji', 'secupress' ), '🍅' => _x( 'Tomato', 'emoji', 'secupress' ) ];
	$sets['chars']     = [ '🤖' => _x( 'Robot', 'emoji', 'secupress' ), '🤡' => _x( 'Clown', 'emoji', 'secupress' ),  '👻' => _x( 'Ghost', 'emoji', 'secupress' ),  '👽' => _x( 'Alien', 'emoji', 'secupress' ),   '💩' => _x( 'Poo', 'emoji', 'secupress' )    ];
	$sets['food']      = [ '🍞' => _x( 'Bread', 'emoji', 'secupress' ), '🧀' => _x( 'Cheese', 'emoji', 'secupress' ), '🥩' => _x( 'Steak', 'emoji', 'secupress' ),  '🧈' => _x( 'Butter', 'emoji', 'secupress' ),  '🥗' => _x( 'Salad', 'emoji', 'secupress' )  ];
	$sets['ffood']     = [ '🌮' => _x( 'Taco', 'emoji', 'secupress' ),  '🌭' => _x( 'Hotdog', 'emoji', 'secupress' ), '🍕' => _x( 'Pizza', 'emoji', 'secupress' ),  '🍔' => _x( 'Burger', 'emoji', 'secupress' ),  '🍟' => _x( 'Fries', 'emoji', 'secupress' )  ];
	$sets['space']     = [ '🌍' => _x( 'Earth', 'emoji', 'secupress' ), '✨' => _x( 'Stars', 'emoji', 'secupress' ),  '🌜' => _x( 'Moon', 'emoji', 'secupress' ),   '☀️' => _x( 'Sun', 'emoji', 'secupress' ),     '☄️' => _x( 'Comet', 'emoji', 'secupress' )  ];
	$sets['objects']   = [ '🎩' => _x( 'Hat', 'emoji', 'secupress' ),   '👋' => _x( 'Hand', 'emoji', 'secupress' ),   '👁️' => _x( 'Eye', 'emoji', 'secupress' ),    '👓' => _x( 'Glasses', 'emoji', 'secupress' ), '🚗' => _x( 'Car', 'emoji', 'secupress' )    ];
	$sets['objects2']  = [ '🏠' => _x( 'House', 'emoji', 'secupress' ), '🎹' => _x( 'Piano', 'emoji', 'secupress' ),  '⚽️' => _x( 'Ball', 'emoji', 'secupress' ),   '🍪' => _x( 'Cookie', 'emoji', 'secupress' ),  '⭐️' => _x( 'Star', 'emoji', 'secupress' )   ];
	
	$sets  = apply_filters( 'secupress.plugins.emojisets', $sets );

	unset( $sets['all'], $sets['random'] ); // Don't set those names, see docblock.

	if ( 'all' === $set ) {
		return $sets;
	}

	if ( 'random' === $set ) {
		$sets = secupress_shuffle_assoc( $sets );
		return reset( $sets );
	}

	if ( ! isset( $sets[ $set ] ) ) {
		return reset( $sets );
	}

	return $sets[ $set ];
}

add_filter( 'authenticate', 'secupress_force_strong_encryption_remove_blind_password', 0, 3 );
/**
 * Remove the suffix and set back the old password when the module "Prevent Other Encryption System to Log In" is not active
 * (Needed outside the module when deactivated)
 *
 * @since 2.3.21
 * @author Julio Potier
 * 
 * @see secupress_force_strong_encryption_blind_password_set_password()
 * 
 * @param (WP_User|WP_Error) $user
 * @param (string) $username
 * @param (string) $password
 * 
 * @return (WP_User|WP_Error)
 **/
function secupress_force_strong_encryption_remove_blind_password(
	$user,
	$username,
	#[\SensitiveParameter]
	$password
) {
	if ( secupress_is_submodule_active( 'users-login', 'force-strong-encryption' ) ) {
		return $user;
	}

	$_user   = secupress_get_user_by( $username );
	if ( ! secupress_is_user( $_user ) ) {
		return $user;
	}

	$suffix  = get_user_meta( $_user->ID, 'secupress-blind-password', true );
	if ( ! $suffix ) {
		return $user;
	}

	$hash    = secupress_generate_key_for_object( $_user->ID );
	$passwor = $password . $hash;
	$valid   = wp_check_password( $passwor, $_user->user_pass, $_user->ID );
	
	if ( ! $valid ) {
		return $user;
	}

	// Do not warn, this is not a hack, nobody has to know that now.
	remove_all_actions( 'wp_set_password' );
	// Set back the old password
	wp_set_password( $password, $_user->ID );

	delete_user_meta( $_user->ID, 'secupress-blind-password' );

	return $_user;
}

/**
 * Get the best encryption algo for the installation
 *
 * @since 2.3.21
 * @author Julio Potier
 * 
 * @return (string)
 **/
function secupress_get_best_encryption_system() {
	switch( true ) {
		case defined( 'PASSWORD_ARGON2ID' ):
			return PASSWORD_ARGON2ID;
		break;
		case defined( 'PASSWORD_ARGON2I' ):
			return PASSWORD_ARGON2I;
		break;
		case defined( 'PASSWORD_BCRYPT' ):
			return PASSWORD_BCRYPT;
		break;
		default:
			return PASSWORD_DEFAULT;
		break;
	}
}

/**
 * Get the name of the encryption algo
 *
 * @since 2.3.21
 * @author Julio Potier
 * 
 * @param (string) $system
 * 
 * @return (string)
 **/
function secupress_get_encryption_name( $system ) {
	switch( $system ) {
		case '2y':
			return 'Bcrypt';
		break;
		case 'argon2i':
			return 'Argon2I';
		break;
		case 'argon2id':
			return 'Argon2ID';
		break;
		default:
			return ucfirst( $system );
		break;
	}
}

/**
 * Get the DB prefix for an algo
 *
 * @since 2.3.21
 * @author Julio Potier
 * 
 * @param (string) $system
 * 
 * @return (string)
 **/
function secupress_get_encryption_prefix( $system ) {
	switch( $system ) {
		case '2y': // WP BCRYPT
			return '$wp$2y$';
		break;
		case 'argon2i':
			return '$argon2i$';
		break;
		case 'argon2id':
			return '$argon2id$';
		break;
		default: // DEF BCRYPT
			return '$2y$';
		break;
	}
}

/**
 * Get the best cost for an algo
 *
 * @since 2.3.21
 * @author Julio Potier
 * 
 * @param (string) $algo
 * 
 * @return 
 **/
function secupress_get_best_cost_by_algo( $algo ) {
	$mem_max             = secupress_get_max_memory();
	$args                = [];
	$args['algo']        = $algo;
	$args['memory_cost'] = $mem_max * 64; // 6.4% of max memory is enough
	$args['cost']        = 4;
	if ( '2y' === $algo ) {
		$via_php      = version_compare( PHP_VERSION, '8.4', '>=' ) ? 12 : 10;
		$thresholds   = [ 256, 512, 1024, 2048 ];
		$args['cost'] = $via_php;

		foreach ( $thresholds as $threshold ) {
			if ( $mem_max >= $threshold ) {
				++$args['cost'];
			}
		}
	} elseif ( false !== strpos( $algo, 'argon' ) ) {
		$args['cost']    = 3 + min( 4, max( 1, $mem_max === -1 ? 4 : (int) ( log( $mem_max ) / log( 2 ) - 6 ) ) ); // 6=128=2^7
	}
	$args                = apply_filters( 'secupress.algo.args', $args, $algo );
	return $args;
}

/**
 * Add a rehash meta to any user who needs it
 * 
 * @internal Starts with "_": DO NOT USE ANYWHERE!
 * @see secupress_password_policy_settings_callback()
 * 
 * @since 2.3.21
 * @author Julio Potier
 * 
 * @return (bool) True if at least 1 user needed a rehash
 **/
function _secupress_force_strong_encryption_set_rehash_meta() {
	global $wpdb;

	$prefix = secupress_get_encryption_prefix( secupress_get_best_encryption_system() );
	$sql    = $wpdb->prepare( 'SELECT ID FROM ' . $wpdb->users . ' WHERE user_pass NOT LIKE %s', $prefix . '%' );
	$ids    = $wpdb->get_col( $sql );
	if ( ! $ids ) {
		return false;
	}
	foreach ( $ids as $_id ) {
		// @see secupress_prevent_hash_reuse_password_needs_rehash()
		update_user_meta( $_id, 'secupress-password-needs-rehash', 1 );
	}
	return true;
}

/**
 * Return the max memory on this server/host
 *
 * @since 2.3.21
 * @author Julio Potier
 * 
 * @return (int) $mem
 **/
function secupress_get_max_memory() {
	$mem = (int) ini_get('memory_limit');
	if ( -1 === $mem ) {
		$mem = 2; // Gb ; No limit? Let's say 2 Gb then
	}
	if ( $mem < 16 ) { // Mb ; Less than 16Mb? Should be Gb then, multiply.
		$mem *= 1024;
	}
	return $mem;
}

/**
 * Move Login: return the list of customizable login actions.
 *
 * @since 1.0
 * @since 1.3.1 Remove all other slugs than "login"
 * @since 1.3.2 Remove SFML hook, not compatible anymore
 *
 * @return (array) Return an array with the action names as keys and field labels as values.
 */
function secupress_move_login_slug_labels() {
	$labels = [ // WP i18n strings.
		'login'               => __( 'Log in' ),
		'logout'              => __( 'Log out' ),
		// 'register'           => __( 'Register' ),
		'lostpassword'        => __( 'Lost Password' ),
		'resetpass'           => __( 'Password Reset' ),
		'confirm_admin_email' => __( 'Confirm Admin Email' ),
	];
	if ( '1' === get_option( 'users_can_register' ) ) {
		$labels['register']   = __( 'Register' );
	}

	/**
	 * Add custom actions to the list of customizable actions. Backcompat for SFML.
	 *
	 * @since 2.4.1
	 *
	 * @param (array) $new_slugs An array with the action names as keys and field labels as values. An empty array by default.
	*/
	$new_slugs = apply_filters( 'sfml_additional_slugs', [] );
	/**
	 * Add custom actions to the list of customizable actions.
	 *
	 * @since 2.4.1
	 *
	 * @param (array) $new_slugs An array with the action names as keys and field labels as values. An empty array by default.
	*/
	$new_slugs = apply_filters( 'secupress.plugins.movelogin.additional_slugs', $new_slugs );

	if ( $new_slugs && is_array( $new_slugs ) ) {
		$new_slugs = array_unique( $new_slugs );
		$new_slugs = array_diff_key( $new_slugs, $labels );
		$labels    = array_merge( $labels, $new_slugs );
	}

	return $labels;
}
