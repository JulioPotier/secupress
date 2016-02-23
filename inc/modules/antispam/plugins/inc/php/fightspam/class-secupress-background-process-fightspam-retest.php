<?php
defined( 'ABSPATH' ) or die( 'Cheatin\' uh?' );


/**
 * Background Antispam Retest class.
 *
 * @package SecuPress
 * @since 1.0
 */

class SecuPress_Background_Process_Fightspam_Retest extends WP_Background_Process {

	const VERSION = '1.0';

	/**
	 * @var string
	 */
	protected $prefix = 'secupress';

	/**
	 * @var string
	 */
	protected $action = 'fightspam_retest';

	/**
	 * @var The reference to the instance of this class.
	 */
	protected static $_instance;


	/**
	 * Get the instance of this class.
	 *
	 * @since 1.0
	 *
	 * @return Singleton The *Singleton* instance.
	 */
	final public static function get_instance() {
		if ( ! isset( static::$_instance ) ) {
			static::$_instance = new static;
		}

		return static::$_instance;
	}


	/**
	 * Task: test again a comment for spam.
	 *
	 * @param (int) $comment_ID A comment ID.
	 *
	 * @return (bool) false to remove the item from the queue.
	 */
	protected function task( $comment_ID ) {
		$comment_ID  = (int) $comment_ID;
		$commentdata = get_comment( $comment_ID, ARRAY_A );

		if ( ! $commentdata ) {
			// Remove from queue.
			return false;
		}

		$comment_approved = secupress_fightspam_author_as_spam_check( $commentdata['comment_approved'], $commentdata );

		if ( $comment_approved ) {
			// Not an error: update status.
			if ( 'spam' === $comment_approved ) {

				wp_spam_comment( $comment_ID );
				static::_handle_child_comments( $comment_ID );

			} elseif ( 'trash' === $comment_approved ) {

				wp_trash_comment( $comment_ID );
				static::_handle_child_comments( $comment_ID );

			} elseif ( 'approve' === $comment_approved || '1' === $comment_approved || 1 === $comment_approved ) {

				wp_set_comment_status( $comment_ID, 'approve' );

			}
		} else {
			// Schedule a new test.
			secupress_fightspam_schedule_retest( $comment_ID );
		}

		// Remove from queue.
		return false;
	}


	/**
	 * Send child comments to trash recursively.
	 * We'll trash only comments with status 'hold' (`comment_status=0`) and 'approve' (`comment_status=1`).
	 *
	 * @param (int) $comment_ID A comment ID.
	 */
	protected static function _handle_child_comments( $comment_ID ) {
		global $wpdb;

		if ( ! $comment_ID ) {
			return;
		}

		$all = array();

		// Get this comment's child comments.
		$ids = $wpdb->get_col( $wpdb->prepare( "SELECT comment_ID from $wpdb->comments WHERE comment_parent = %d", $comment_ID ) );

		// As long as we find some, dig deeper.
		while ( $ids ) {
			$ids = array_map( 'absint', $ids );
			$all = array_merge( $all, $ids );
			$ids = implode( ',', $ids );
			$ids = $wpdb->get_col( "SELECT comment_ID from $wpdb->comments WHERE comment_parent IN ( $ids )" );
		}

		// If we have some, trash'em.
		if ( $all ) {
			array_map( 'wp_trash_comment', $all );
		}
	}
}
