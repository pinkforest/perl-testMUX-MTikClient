#!/usr/bin/perl

package MTikClient;

use strict;
use warnings;

use POSIX;
use Socket;
use bytes;
use Data::Dumper;
use Digest::MD5;

require Exporter;

my @ISA = qw(Exporter);
my @EXPORT = qw();

use constant {

    ######################################
    # Our package [0] IDX.

    SELF_ID   => 0x00,
    DEBUG_LVL => 0x01,
    OBJ_TMUX  => 0x02,
    DEBUG_FNC => 0x03,

    ######################################
    # Data IDX for FNOs

    T_INBUF_LEN   => 0x01,
    T_INBUF_DATA  => 0x02,
    T_OUTBUF_LEN  => 0x03,
    T_OUTBUF_DATA => 0x04,
    T_STACK_PTR   => 0x05,

    ###
    # Cached peer info (ref may be gone)
    #
    T_PEER_I      => 0x06,

    I_PEER_ADDR   => 0x01,
    I_PEER_PORT   => 0x02,
    I_PEER_OBJ    => 0x03,
    ####

    ###
    # Internal states
    #
    T_STATE       => 0x08,

    ST_CONNECT_INIT    => 0x01,
    ST_CONNECT_OK      => 0x02,
    ST_LOGIN_INIT      => 0x03,
    ST_LOGIN_TRY       => 0x04,
    ST_LOGIN_OK        => 0x05,
    ####

    T_PARAMS      => 0x09,

    # FNO Index end.
    ######################################

    CRLF          => "\r\n"	
};

sub __debug($$) {
    my $self = shift;

    return if !ref($self->[DEBUG_FNC]);

    $self->[DEBUG_FNC](@_);
}

sub t_fmt_ascii($) {
    return ( join("", map { $_ = ord(); ( $_>126 || $_<32 ? sprintf("<%02X>",$_) : chr() ) } split("",shift)) );
}

sub _closeClient($$;$$) {
    my ($self, $_fno, $err, $errNo) = (@_);
    $self->__debug(5,$_fno, __PACKAGE__.':'.__LINE__.'-_closeClient() Clear TCPConnector'.(defined($err)?': '.$err:''));

    $self->[OBJ_TMUX]->del($_fno);

}

sub _pakLen($) {
    my $_l = shift;
    my ($_els);

    if ($_l < 0x80) {
        $_els =chr($_l);
    }
    elsif ($_l < 0x4000) {
        $_l |= 0x8000;
        $_els  = chr(($_l >> 8) & 0xFF);
        $_els .= chr($_l & 0xFF);
    }
    elsif ($_l < 0x200000)
    {
        $_l |= 0xC00000;
        $_els  = chr(($_l >> 16) & 0xFF);
        $_els .= chr(($_l >> 8) & 0xFF);
        $_els .= chr($_l & 0xFF);
    }
    elsif ($_l < 0x10000000)
    {
        $_l |= 0xE0000000;
        $_els  = chr(($_l >> 24) & 0xFF);
        $_els .= chr(($_l >> 16) & 0xFF);
        $_els .= chr(($_l >> 8) & 0xFF);
        $_els .= chr($_l & 0xFF);
    }
    return $_els;
}

sub _xtractSentence($$) {
    my ($self, $_fno) = (@_);
    my ($_wc, $_fc) = (0, undef);
    my $_words = [];

    my $_d = $self->[OBJ_TMUX][$_fno][$self->[SELF_ID]];

    $_d->[T_STACK_PTR] = 0 if ! defined ( $_d->[T_STACK_PTR] );

    return undef if ( $_d->[T_STACK_PTR] >= $_d->[T_INBUF_LEN] );

    my $_csptr = $_d->[T_STACK_PTR];
    
    ##################
    # Extract words.
    while ( $_fc = ord ( substr($_d->[T_INBUF_DATA], $_csptr, 1) ) ) {

	my $_glen  = ( $_d->[T_INBUF_LEN] - $_csptr);
	
	if ( $_glen <= 0 ) {
	    $self->__debug(5,$_fno, __PACKAGE__.
			   ':'.__LINE__.
			   '-_xtractSentence(_fno='.$_fno.') /*** BUG -> Over bounds? -> '.$_csptr.' on glen -> '.$_glen.' ***/');
	    return(undef);
	}


	my $_wlen = 0;

	###########
        # 4 bytes                                                       
        if ( ( $_fc & 0xE0 ) == 0xE0 ) {
            if ( $_glen >= 4 ) {
                $_wlen = hex( unpack( "H*", chr($_fc & 0x1f).substr($_d->[T_INBUF_DATA], ($_csptr+1), 3) ) );
		$_csptr+=4;
		$_glen-=4;
            }
        }
        # 3 bytes                                                                                                               
        elsif ( ( $_fc & 0xC0 ) == 0xC0 ) {
            if ( $_glen >= 3 ) {
                $_wlen = hex( unpack( "H*", chr($_fc & 0x3f).substr($_d->[T_INBUF_DATA], ($_csptr+1), 2) ) );
		$_csptr+=3;
		$_glen-=3;
            }
        }
        # 2 bytes                                                                                                               
        elsif ( ( $_fc & 0x80 ) == 0x80 ) {
            if ( $_glen >= 2 ) {
                $_wlen = hex ( unpack( "H*", chr($_fc & 0x7f). substr($_d->[T_INBUF_DATA], ($_csptr+1), 1) ) );
		$_csptr+=2;
		$_glen-=2;
            }
        }
        elsif( ( $_fc > 0 && $_fc <= 0x7F ) ) {
            $_wlen = $_fc;
	    $_csptr++;
	    $_glen--;
        }

	$self->__debug(5,$_fno, __PACKAGE__.
		       ':'.__LINE__.
		       '-_xtractSentence(_fno='.$_fno.') _CSPTR('.$_csptr.')'.
		       ' WordLen='.$_wlen.' _glen='.$_glen);

	if ( $_wlen > 0 && $_glen > $_wlen ) {
	    my $_word = substr($_d->[T_INBUF_DATA], $_csptr, $_wlen );
	    push(@{$_words}, $_word); 
	    $_csptr += $_wlen;
	}
	else {
	    $self->__debug(5,$_fno, __PACKAGE__.
			   ':'.__LINE__.
			   '-_xtractSentence(_fno='.$_fno.') _CSPTR('.$_csptr.')'.
			   ' Not enough data in buffer for wordLen -> '.$_wlen.' where _csptr='.$_csptr.' _fc='.$_fc.' _glen='.$_glen);
	    return(undef);
	}
    }

    if ( !defined($_fc) || $_fc != 0 ) {
	$self->__debug(5,$_fno, __PACKAGE__.
		       ':'.__LINE__.
		       '-_xtractSentence(_fno='.$_fno.') _CSPTR('.
		       $_csptr.')  /*** BUG T_STACK_PTR -> '.$_d->[T_STACK_PTR].
		       ' T_INBUF_LEN -> '.$_d->[T_INBUF_LEN].' Weird _fc ?! return='.( defined ( $_fc ) ? $_fc : 'n/A').' ***/');

	return(undef);
    }

    if ( ! scalar ( @{$_words} ) ) {

	$self->__debug(5,$_fno, __PACKAGE__.
		       ':'.__LINE__.
		       '-_xtractSentence(_fno='.$_fno.') _CSPTR('.
		       $_csptr.')  /*** BUG T_STACK_PTR -> '.$_d->[T_STACK_PTR].
		       ' T_INBUF_LEN -> '.$_d->[T_INBUF_LEN].' No words??? ***/');
	die;
    }

    $_csptr++;
   
    $self->__debug(5,$_fno, __PACKAGE__.
		   ':'.__LINE__.
		   '-_xtractSentence(_fno='.$_fno.') **OK** -> _CSPTR('.$_csptr.')  T_STACK_PTR -> '.
		   $_d->[T_STACK_PTR].
		   ' T_INBUF_LEN -> '.$_d->[T_INBUF_LEN].' Words extracted: '.join(",", @{$_words}));
    
    $_d->[T_STACK_PTR] = $_csptr;

    return($_words);
}

sub _sendClient($$$) {
    my ($self, $_fno, $_data) = (@_);
    my $_d = $self->[OBJ_TMUX][$_fno][$self->[SELF_ID]];

    my $_olen = bytes::length($_data);

    if ( $_olen > 0 ) {

	$_d->[T_OUTBUF_DATA] .= $_data;
	$_d->[T_OUTBUF_LEN]  += $_olen;

	$self->[OBJ_TMUX]->mOUT($_fno, 1);

    }

    return($_olen);
}

sub _sendMtik($$$) {
    my ($self, $_fno, $_sntcs) = (@_);
    my $_d = $self->[OBJ_TMUX][$_fno][$self->[SELF_ID]];
    my ($_ret, $_sntc, $_data) = (0, 0, '');

    $self->__debug(5,$_fno, __PACKAGE__.
                   ':'.__LINE__.
                   '-_sendMtik(_fno='.$_fno.', _sntcs='.t_fmt_ascii(Dumper($_sntcs)).')');

    $_sntc = scalar(@{$_sntcs}) if defined(@{$_sntcs});

    $self->__debug(5, $_fno, '_sendMtik sentences '.$_sntc);

    return 0 if !$_sntc;

    # sentences
    for(my $snti=0;$snti<=($_sntc-1);$snti++) {
	my $wrdc = scalar(@{$_sntcs->[$snti]});
	next if !$wrdc;

	$self->__debug(5, $_fno, '_sendMtik sentence<'.$snti.'> words = '.$wrdc);

	for(my $wrdi=0;$wrdi<=($wrdc-1);$wrdi++) {
	    $_ret++;

	$self->__debug(5, $_fno, '_sendMtik sentence<'.$snti.'> word<'.$wrdi.'> = '.$_sntcs->[$snti][$wrdi]);
	    $_data .= _pakLen(bytes::length($_sntcs->[$snti][$wrdi])).$_sntcs->[$snti][$wrdi];
	}
	$_data .= "\0";
    }

    $self->_sendClient($_fno, $_data);

    return $_ret;
}

sub hookTCPConnector($$$) {
    my ($self, $_fd, $_fno) = (@_);
    $self->[OBJ_TMUX][$_fno][$self->[SELF_ID]] = [];
    my $_d = $self->[OBJ_TMUX][$_fno][$self->[SELF_ID]];

    $self->__debug(5, __PACKAGE__.':'.__LINE__.' hookTCPConnector('.$self.', '.$_fd.')');

    $_d->[T_PEER_I][I_PEER_OBJ]  = $_fd;

    $_d->[T_INBUF_LEN] = 0;
    $_d->[T_INBUF_DATA] = '';

    $_d->[T_OUTBUF_LEN] = 0;
    $_d->[T_OUTBUF_DATA] = '';

    $_d->[T_STATE] = ST_CONNECT_INIT;

    return(0);
}

sub unhookTCPConnector($$) {
    my ($self, $_fno) = (@_);

    $self->__debug(5, __PACKAGE__.':'.__LINE__.' unhookTCPConnector('.$self.', '.$_fno.')');

    $self->[OBJ_TMUX][$_fno][$self->[SELF_ID]] = undef;
    delete $self->[OBJ_TMUX][$_fno][$self->[SELF_ID]];

    return(0);
}

sub login($$$$$) {
    my ($self, $_fno, $_u, $_p, $_caller, $_callback) = (@_);
    my $_d = $self->[OBJ_TMUX][$_fno][$self->[SELF_ID]];

    $self->[OBJ_TMUX]->setCallback($_fno, $_caller, $_callback) if defined ($_caller) && defined($_callback);

    if ( ! defined ( $_d->[T_STATE] ) ) {
	$self->[OBJ_TMUX]->sendParent($_fno, 1, 'ERROR No such/Not valid client - No state.');
	return(1);
    }

#    if ( $self->[$_fno][T_STATE] != ST_CONNECT_OK ) {
#	$self->_sendParent($_fno, 2, 'Client must be in ST_CONNECT_OK state. Current<'.$self->[$_fno][T_STATE].'>');
#	return(2);
#    }

    $self->[OBJ_TMUX]->sendParent($_fno, 0, 'INFO Initiated login request. Waiting for the challenge.');

    $self->_sendMtik($_fno, [['/login']]);
    $_d->[T_STATE]  = ST_LOGIN_INIT;
    $_d->[T_PARAMS] = [$_u, $_p];

    return(0);
}

sub _process_io_error($$$) {
    my ($self, $_fno, $errNo) = (@_);
    my $_d = $self->[OBJ_TMUX][$_fno][$self->[SELF_ID]];

    my $errStr = POSIX::strerror($errNo);

    $self->__debug(5, $_fno, __PACKAGE__.':'.__LINE__.'-__process_error() errNo['.$errNo.'>] -> '.$errStr);

    if ( $errNo ) {

	#####################
	# Close on != EAGAIN
	if ( $errNo != POSIX::EAGAIN ) {
	    $self->[OBJ_TMUX]->sendParent($_fno, 255, 'DEAD IOError['.$errNo.']: '.$errStr);
	    $self->_closeClient($_fno, $errStr, $errNo);
	}
    }
    else {
	$self->__debug(5, $_fno, __PACKAGE__.':'.__LINE__.'-__process_error() errNo['.$errNo.'>] - No handler for error');
	return(-1);
    }

    return($errNo);
}

sub handler_in($$) {
    my ($self, $_fno) = (@_);
    my $_d = $self->[OBJ_TMUX][$_fno][$self->[SELF_ID]];

    $self->__debug(5, $_fno, __PACKAGE__.':'.__LINE__.' handler_in('.$self.', '.$_fno.')');


    my ($tRead, $b) = (0,0);

    # ++TODO:Some security (MitM can flood input buffer..)
    while ( $b = sysread( $_d->[T_PEER_I][I_PEER_OBJ], $_d->[T_INBUF_DATA], 8192, $_d->[T_INBUF_LEN] ) ) {
	$self->__debug(5,$_fno, 'Socket '.$_fno.' += '.$b.' DATA: '.t_fmt_ascii($_d->[T_INBUF_DATA]));
	$tRead += $b;
	$_d->[T_INBUF_LEN] += $b;
	
	last if $b < 8192;;
	
    }
 
    if ( my $eno = POSIX::errno() ) {
	return ( $self->_process_io_error($_fno, $eno) );
    }

    if ( defined ( $tRead ) && $tRead > 0 ) {
	my $eLen = 0;

	while ( my $words = $self->_xtractSentence($_fno) ) {

	    my $wordCount = scalar(@{$words});

	    $self->__debug(5,$_fno,__PACKAGE__.':'.__LINE__.'__handler_in(ST='.(defined($_d->[T_STATE])?$_d->[T_STATE]:0).') _xtractNext WORDS -> '.join(",", @{$words}));

	    #########
	    # Login?
	    if ($_d->[T_STATE] == ST_LOGIN_INIT) {

		if ($words->[0] eq '!done' ) {
		    if ( defined ( $words->[1] ) && $words->[1] =~ /^=ret=([a-f0-9A-F]+)$/o ) {
			my ($_chlg) = ($1);
			$self->__debug(5,$_fno,__PACKAGE__.':'.__LINE__.'__handler_in() ST_LOGIN_INIT Challenge<'.$_chlg.'>');

			my $_dig = Digest::MD5->new;
			$_dig->add("\0". $_d->[T_PARAMS][1]. pack("H*", $_chlg));

			$self->_sendMtik($_fno, [['/login',
						  '=name='.$_d->[T_PARAMS][0],
						  '=response=00'.$_dig->hexdigest]]);

			$_d->[T_STATE] = ST_LOGIN_TRY;

			$self->[OBJ_TMUX]->sendParent($_fno, 0, 'INFO Challenge received & Responded');

		    }
		}
	    }
	    elsif($_d->[T_STATE] == ST_LOGIN_TRY) {
		if ( $wordCount==1 && $words->[0] eq '!done' ) {
		    $_d->[T_STATE] = ST_LOGIN_OK;
		    $self->[OBJ_TMUX]->sendParent($_fno, 0, 'OK Logged in.');
		}
	    }
	    else {
		if ( $words->[0] eq '!re' ) {
		    $self->[OBJ_TMUX]->sendParent($_fno, 0, '!re '.join(" ", @{$words}));
		}
		elsif ( $words->[0] eq '!done' ) {
		    $self->[OBJ_TMUX]->sendParent($_fno, 0, '!done '.join(" ", @{$words}));
		}
		else {
		    $self->[OBJ_TMUX]->sendParent($_fno, 42, 'UNHANDLED '.join(" ", @{$words}));
		}
	    }

	    if ($words->[0] eq '!trap' ) {
		$self->[OBJ_TMUX]->sendParent($_fno, 42, 'TRAP '.join(" ", @{$words}));
	    }
	}

	if ( $_d->[T_STACK_PTR] > 0 ) {
	    $_d->[T_INBUF_DATA] = substr($_d->[T_INBUF_DATA], $_d->[T_STACK_PTR]);
	    $_d->[T_INBUF_LEN] -= $_d->[T_STACK_PTR];
	    $_d->[T_STACK_PTR] = 0;
	}

    }

   
    ######################
    # Signalled close
    if ( defined($b) && $b == 0 && !$tRead ) {
	$self->[OBJ_TMUX]->sendParent($_fno, 255, 'DEAD Server closed the client connection.');
	$self->_closeClient($_fno, $!);
    }

    return(0);

}

sub handler_out($$) {
    my ($self, $_fno) = (@_);
    my $_d = $self->[OBJ_TMUX][$_fno][$self->[SELF_ID]];

    $self->__debug(5, $_fno, __PACKAGE__.':'.__LINE__.' handler_out('.$self.', '.$_fno.')');

    ############################################
    # Connection established (Non blocking TCP)
    if ( $_d->[T_STATE] == ST_CONNECT_INIT ) {
	$_d->[T_STATE] = ST_CONNECT_OK;
	$self->[OBJ_TMUX]->sendParent($_fno, 0, 'OK Connected to peer.');
    }

    if ( $_d->[T_OUTBUF_LEN] == 0 ) {
	$self->[OBJ_TMUX]->mOUT($_fno, 0);
	return(0);
    }

    my $_wb = syswrite($_d->[T_PEER_I][I_PEER_OBJ], $_d->[T_OUTBUF_DATA], $_d->[T_OUTBUF_LEN]);

    $self->__debug(5,$_fno, 'WB='.$_wb.' vs '.$_d->[T_OUTBUF_LEN]);

    if ( defined ( $_wb ) ) {
                    
	if($_wb == $_d->[T_OUTBUF_LEN]) {
	    $_d->[T_OUTBUF_DATA] = '';
	    $_d->[T_OUTBUF_LEN] = 0;

	    $self->[OBJ_TMUX]->mOUT($_fno, 0);

	}
	else {
	    $_d->[T_OUTBUF_DATA] = substr(  $_d->[T_OUTBUF_DATA], $_wb );
	}
    }

    return(0);
}

sub handler_err($$) {
    my ($self, $_fno) = (@_);

    my ($eno, $errstr) = ($!+0, $!);

    $self->__debug(5, $_fno, __PACKAGE__.':'.__LINE__.' handler_out('.$self.', '.$_fno.')');

    $self->_closeClient($_fno, $errstr, $eno);

    return(0);
}

sub myID($;$) {
    my ($self, $_id) = (@_);

    if ( defined ( $_id ) ) {
	$self->[SELF_ID] = $_id;
    }

    return($self->[SELF_ID]);
}

sub new {
    my $class = shift;
    my ($opts) = shift;
    my $self = [];
    bless $self, $class;

    $self->[DEBUG_LVL]  = ( defined($opts->{'debug'}) ? $opts->{'debug'} : 0 );
    $self->[DEBUG_FNC]  = ( $self->[DEBUG_LVL] > 0 && defined($opts->{'debugFunc'}) ) ? $opts->{'debugFunc'} : undef ;

    $self->[OBJ_TMUX]     = ( defined($opts->{'tmux'}) ? $opts->{'tmux'} : undef );

    $self->__debug(2, 0, 'TMUX<'.__PACKAGE__.'> Reference = '.$self->[OBJ_TMUX]);

    $self->__debug(2, 0, '__INITIALIZE__','OK');

    return $self;
}

1;
