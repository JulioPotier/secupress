<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );


/**
 * Background Antispam Retest class.
 *
 * @package SecuPress
 * @since 1.0
 */
class SecuPress_Background_Process_Fightspam_Retest extends WP_Background_Process {

	const VERSION = '1.0';

	/**
	 * Prefix used to build the global process identifier.
	 *
	 * @var (string)
	 */
	protected $prefix = 'secupress';

	/**
	 * Suffix used to build the global process identifier.
	 *
	 * @var (string)
	 */
	protected $action = 'fightspam_retest';

	/**
	 * The reference to *Singleton* instance of this class.
	 *
	 * @var (object)
	 */
	protected static $_instance;


	/**
	 * Get the instance of this class.
	 *
	 * @since 1.0
	 *
	 * @return (object) The *Singleton* instance.
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
	 * @param (int) $comment_id A comment ID.
	 *
	 * @return (bool) false to remove the item from the queue.
	 */
	protected function task( $comment_id ) {
		$comment_id  = (int) $comment_id;
		$commentdata = get_comment( $comment_id, ARRAY_A );

		if ( ! $commentdata ) {
			// Remove from queue.
			return false;
		}

		$comment_approved = secupress_fightspam_author_as_spam_check( $commentdata['comment_approved'], $commentdata );

		if ( $comment_approved ) {
			// Not an error: update status.
			if ( 'spam' === $comment_approved ) {

				wp_spam_comment( $comment_id );
				static::handle_child_comments( $comment_id );

			} elseif ( 'trash' === $comment_approved ) {

				wp_trash_comment( $comment_id );
				static::handle_child_comments( $comment_id );

			} elseif ( 'approve' === $comment_approved || '1' === $comment_approved || 1 === $comment_approved ) {

				wp_set_comment_status( $comment_id, 'approve' );

			}
		} else {
			// Schedule a new test.
			secupress_fightspam_schedule_retest( $comment_id );
		}

		// Remove from queue.
		return false;
	}


	/**
	 * Send child comments to trash recursively.
	 * We'll trash only comments with status 'hold' (`comment_status=0`) and 'approve' (`comment_status=1`).
	 *
	 * @param (int) $comment_id A comment ID.
	 */
	protected static function handle_child_comments( $comment_id ) {
		global $wpdb;

		if ( ! $comment_id ) {
			return;
		}

		$all = array();

		// Get this comment's child comments.
		$ids = $wpdb->get_col( $wpdb->prepare( "SELECT comment_ID from $wpdb->comments WHERE comment_parent = %d", $comment_id ) );

		// As long as we find some, dig deeper.
		while ( $ids ) {
			$ids = array_map( 'absint', $ids );
			$all = array_merge( $all, $ids );
			$ids = implode( ',', $ids );
			$ids = $wpdb->get_col( "SELECT comment_ID from $wpdb->comments WHERE comment_parent IN ( $ids )" ); // WPCS: unprepared SQL ok.
		}

		// If we have some, trash'em.
		if ( $all ) {
			array_map( 'wp_trash_comment', $all );
		}
	}
}
