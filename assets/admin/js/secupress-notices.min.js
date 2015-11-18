(function($, d, w, undefined) {

	// Make our notices dismissible.
	$( ".notice.secupress-is-dismissible" ).each( function() {
		var $this = $( this ),
			$button = $( '<button type="button" class="notice-dismiss"><span class="screen-reader-text"></span></button>' ),
			btnText = SecuPressi18nNotices.dismiss || '';

		// Ensure plain text
		$button.find( ".screen-reader-text" ).text( btnText );

		$this.append( $button );

		$button.on( "click.wp-dismiss-notice", function( event ) {
			var noticeId = $this.data( "id" );
			event.preventDefault();

			if ( undefined !== noticeId && noticeId ) {
				$.post( ajaxurl, {
					action: "secupress_dismiss-notice",
					notice_id: noticeId,
					_nonce: SecuPressi18nNotices.nonce
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