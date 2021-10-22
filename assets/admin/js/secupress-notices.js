/* globals jQuery: false, ajaxurl: false, SecuPressi18nNotices: false */
(function($, d, w, undefined) {

	// Make our notices dismissible.
	$( ".notice.secupress-is-dismissible" ).each( function() {
		var $this    = $( this ),
			noticeId = $this.data( "id" ),
			$button, btnText;

		if ( undefined !== noticeId && noticeId ) {
			$button = $this.find( ".notice-dismiss" );
		} else {
			noticeId = false;
			$button  = $( '<button type="button" class="notice-dismiss"><span class="screen-reader-text"></span></button>' );
			btnText  = SecuPressi18nNotices.dismiss || '';
			// Ensure plain text
			$button.find( ".screen-reader-text" ).text( btnText );
			// Add the button
			$this.append( $button );
		}

		$button.on( "click.wp-dismiss-notice", function( e ) {
			e.preventDefault();

			if ( noticeId ) {
				$.post( ajaxurl, {
					action: "secupress_dismiss-notice",
					notice_id: noticeId,
					_wpnonce: SecuPressi18nNotices.nonce
				} );
			}

			$this.fadeTo( 100 , 0, function() {
				$( this ).slideUp( 100, function() {
					$( this ).remove();
				} );
			} );
		} );
	} );

} )(jQuery, document, window);
