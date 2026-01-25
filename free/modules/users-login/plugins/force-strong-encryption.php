<?php
/**
 * Module Name: Force Strong Encryption
 * Description: Use a strong encryption system with a high cost value.
 * Main Module: users_login
 * Author: SecuPress
 * Version: 2.3.21
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );

// EMERGENCY BYPASS!
if ( defined( 'SECUPRESS_ALLOW_LOGIN_ACCESS' ) && SECUPRESS_ALLOW_LOGIN_ACCESS ) {
	return;
}

$req_wp_ver  = '6.8'; // 6.8 because of encapsulated wp dev
$is_wp_ok    = secupress_wp_version_is( $req_wp_ver );
if ( ! $is_wp_ok ) {
	return;
}

if ( secupress_is_pro() ) {
	require( SECUPRESS_PRO_MODULES_PATH . 'users-login/plugins/force-strong-encryption-pro.php' );
}

/** --------------------------------------------------------------------------------------------- */
/** ACTIVATION / DEACTIVATION =================================================================== */
/** --------------------------------------------------------------------------------------------- */

add_action( 'secupress.modules.deactivate_submodule_' . basename( __FILE__, '.php' ), 'secupress_force_strong_encryption_deactivation' );
add_action( 'secupress.plugins.deactivation', 'secupress_force_strong_encryption_deactivation' );
/**
 * On module deactivation, remove all user meta.
 *
 * @since 2.3.21
 * @author Julio Potier
 */
function secupress_force_strong_encryption_deactivation() {
	delete_metadata( 'user', false, 'secupress-password-needs-rehash', '', true );
	secupress_set_option( 'strong_encryption_system', [] );
}

add_action( 'secupress.modules.activate_submodule_' . basename( __FILE__, '.php' ), 'secupress_force_strong_encryption_activation' );
add_action( 'secupress.plugins.activation', 'secupress_force_strong_encryption_activation' );
/**
 * On module activation, set the algo and cost.
 *
 * @since 2.3.21
 * @author Julio Potier
 */
function secupress_force_strong_encryption_activation() {
	$algo = secupress_get_best_encryption_system();
	$args = secupress_get_best_cost_by_algo( $algo );

	secupress_set_option( 'strong_encryption_system', $args );
}

add_action( 'admin_notices', 'secupress_force_strong_encryption_get_best_encryption_system_notice' );
/**
 * Warn the admins when a better system is available on your site/host
 *
 * @since 2.3.21
 * @author Julio Potier
 **/
function secupress_force_strong_encryption_get_best_encryption_system_notice() {
	if ( ! current_user_can( secupress_get_capability() ) ) {
		return;
	}

	$algo = secupress_get_option( 'strong_encryption_system' );
	$algo = isset( $algo['algo'] ) ? $algo['algo'] : false;
	if ( $algo !== false && secupress_get_best_encryption_system() !== $algo ) {
		$message = sprintf( __( 'The current Password Encryption Method differs from the one selected.<br>The current method is %1$s while the newly detected system is %2$s.<br>Please, %3$sdeactivate and reactivate%4$s the module to use the new one.', 'secupress' ), 
			secupress_tag_me( secupress_get_encryption_name( secupress_get_best_encryption_system() ), 'strong' ),
			secupress_tag_me( secupress_get_encryption_name( $algo ), 'strong' ),
			'<a href="' . secupress_admin_url( 'modules', 'users-login#row-double-auth_force-strong-encryption' ) . '">',
			'</a>'
		);
		secupress_add_notice( $message, 'error', false );
	}
}

add_filter( 'wp_hash_password_algorithm', 'secupress_force_strong_encryption_algo', SECUPRESS_INT_MAX );
/**
 * Force strong encryption algo between PASSWORD_ARGON2ID, PASSWORD_ARGON2I, PASSWORD_BCRYPT
 *
 * @since 2.3.21
 * @author Julio Potier
 * 
 * @return (string)
 */
function secupress_force_strong_encryption_algo() {
	static $notice_done;

	$algo  = secupress_get_option( 'strong_encryption_system' );
	$algo  = isset( $algo['algo'] ) ? $algo['algo'] : PASSWORD_DEFAULT;

	if ( ! $notice_done && ! isset( array_flip( password_algos() )[ $algo ] ) ) {
		$algo        = PASSWORD_DEFAULT;
		$notice_done = true;
		if ( ! current_user_can( secupress_get_capability() ) ) {
			return $algo;
		}

		$message     = sprintf( __( 'The current Password Encryption Method differs from the one selected.<br>The current method is %1$s while the newly detected system is %2$s.<br>Please, %3$sdeactivate and reactivate%4$s the module to use the new one.', 'secupress' ), 
			secupress_tag_me( secupress_get_encryption_name( secupress_get_best_encryption_system() ), 'strong' ),
			secupress_tag_me( secupress_get_encryption_name( $algo ), 'strong' ),
			'<a href="' . secupress_admin_url( 'modules', 'users-login#row-double-auth_force-strong-encryption' ) . '">',
			'</a>'
		);
		secupress_add_notice( $message, 'error', false );
	}
	return $algo;
}

add_filter( 'wp_hash_password_options', 'secupress_force_strong_encryption_opts', SECUPRESS_INT_MAX );
/**
 * Set the correct and best cost for the installation
 *
 * @since 2.3.21
 * @author Julio Potier
 * @param (array) $opts
 * 
 * @return (array) $opts
 */
function secupress_force_strong_encryption_opts( $opts ) {
	$algo = secupress_get_best_cost_by_algo( secupress_force_strong_encryption_algo() );
	switch( $algo['algo'] ) {
		case PASSWORD_ARGON2ID:
		case PASSWORD_ARGON2I:
			if ( isset( $algo['cost'] ) ) {
				$opts['time_cost'] = $algo['cost'];
			}
			if ( isset( $algo['memory_cost'] ) ) {
				$opts['memory_cost'] = $algo['memory_cost'];
			}
		break;
		case PASSWORD_BCRYPT:
			if ( isset( $algo['cost'] ) ) {
				$opts['cost'] = $algo['cost'];
			}
		break;
		case PASSWORD_DEFAULT:
		default:
			$opts = apply_filters( 'secupress.plugins.force-strong-encryption.algo_opts.default', $opts, $algo );
		break;
	}

	return $opts;
}
