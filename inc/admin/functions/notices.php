<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/**
 * Add a notice with the SecuPress_Admin_Notices class.
 *
 * @since 1.0
 *
 * @param (string)      $message    The message to display in the notice.
 * @param (string)      $error_code Like WordPress notices: "error" or "updated". Default is "updated".
 * @param (string|bool) $notice_id  A unique identifier to tell if the notice is dismissible.
 *                                  false: the notice is not dismissible.
 *                                  string: the notice is dismissible and send an ajax call to store the "dismissed" state into a user meta to prevent it to popup again.
 *                                  enpty string: meant for a one-shot use. The notice is dismissible but the "dismissed" state is not stored, it will popup again. This is the exact same behavior than the WordPress dismissible notices.
 */
function secupress_add_notice( $message, $error_code = 'updated', $notice_id = '' ) {
	SecuPress_Admin_Notices::get_instance()->add( $message, $error_code, $notice_id );
}


/**
 * Add a temporary notice with the SecuPress_Admin_Notices class.
 *
 * @since 1.0
 * @since 1.3 Added $notice_id parameter.
 *
 * @param (string)      $message    The message to display in the notice.
 * @param (string)      $error_code Like WordPress notices: "error" or "updated". Default is "updated".
 * @param (string|bool) $notice_id  A unique identifier to tell if the notice is dismissible.
 *                                  false: the notice is not dismissible.
 *                                  string: the notice is dismissible and send an ajax call to store the "dismissed" state into a user meta to prevent it to popup again.
 *                                  enpty string: meant for a one-shot use. The notice is dismissible but the "dismissed" state is not stored, it will popup again. This is the exact same behavior than the WordPress dismissible notices.
 */
function secupress_add_transient_notice( $message, $error_code = 'updated', $notice_id = '' ) {
	SecuPress_Admin_Notices::get_instance()->add_temporary( $message, $error_code, $notice_id );
}


/**
 * Dismiss a notice added with the SecuPress_Admin_Notices class.
 *
 * @since 1.0
 *
 * @param (string) $notice_id The notice identifier.
 * @param (int)    $user_id   User ID. If not set, fallback to the current user ID.
 *
 * @return (bool) true on success.
 */
function secupress_dismiss_notice( $notice_id, $user_id = 0 ) {
	return SecuPress_Admin_Notices::dismiss( $notice_id, $user_id );
}


/**
 * "Undismiss" a notice added with the SecuPress_Admin_Notices class.
 *
 * @since 1.0
 *
 * @param (string) $notice_id The notice identifier.
 * @param (int)    $user_id   User ID. If not set, fallback to the current user ID.
 *
 * @return (bool) true on success.
 */
function secupress_reinit_notice( $notice_id, $user_id = 0 ) {
	return SecuPress_Admin_Notices::reinit( $notice_id, $user_id );
}


/**
 * Test if a notice added with the SecuPress_Admin_Notices class is dismissed.
 *
 * @since 1.0
 *
 * @param (string) $notice_id The notice identifier.
 *
 * @return (bool|null) true if dismissed, false if not, null if the notice is not dismissible.
 */
function secupress_notice_is_dismissed( $notice_id ) {
	return SecuPress_Admin_Notices::is_dismissed( $notice_id );
}
