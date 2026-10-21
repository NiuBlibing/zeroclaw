//! Peer-inbox history admission resolves the existing peer relation at every
//! use. The event stream does not create a new peer/delegation permission.
use super::*;
use zeroclaw_api::{
    principal::PrincipalId,
    session_events::{capture::*, *},
};
use zeroclaw_kernel::session::{
    EffectIntent, PermissionResolver, SessionError,
    engine::{EngineSessionAuthority, EngineSessionSource},
    query::{SessionAccess, SessionAccessPolicy},
};

struct PeerAuthority {
    base: Arc<dyn EngineSessionAuthority>,
    capability: AgentExecutionCapability,
    sender: String,
    recipient: String,
    channel: String,
}
impl PeerAuthority {
    fn current(&self) -> Result<(), SessionError> {
        let handle = self.capability.config_handle();
        let config = handle.read();
        let peers = resolve_peer_set(&config, &self.sender);
        let fallback = self.channel.split_once('.').map(|(kind, _)| kind);
        if config.agent(&self.sender).is_none_or(|agent| {
            !agent.enabled
                || !agent
                    .channels
                    .iter()
                    .any(|channel| *channel == self.channel)
        }) || config
            .agent(&self.recipient)
            .is_none_or(|agent| !agent.enabled)
            || (!peers.is_known_peer(&self.channel, &self.recipient)
                && !fallback.is_some_and(|kind| peers.is_known_peer(kind, &self.recipient)))
        {
            return Err(SessionError::PermissionDenied(
                "peer inbox route revoked".into(),
            ));
        }
        Ok(())
    }
}
impl SessionAccessPolicy for PeerAuthority {
    fn authorize(
        &self,
        principal: &PrincipalId,
        stream: &SessionStreamId,
        access: SessionAccess,
    ) -> Result<(), SessionError> {
        self.current()?;
        SessionAccessPolicy::authorize(self.base.as_ref(), principal, stream, access)
    }
    fn authorize_actor(
        &self,
        actor: &EventActor,
        stream: &SessionStreamId,
        access: SessionAccess,
    ) -> Result<(), SessionError> {
        self.current()?;
        self.base.authorize_actor(actor, stream, access)
    }
}
impl PermissionResolver for PeerAuthority {
    fn authorize(&self, intent: &EffectIntent) -> Result<(), SessionError> {
        self.current()?;
        PermissionResolver::authorize(self.base.as_ref(), intent)
    }
    fn authorize_context(
        &self,
        stream: &SessionStreamId,
        branch: &BranchId,
    ) -> Result<(), SessionError> {
        self.current()?;
        self.base.authorize_context(stream, branch)
    }
    fn authorize_tool(
        &self,
        intent: &EffectIntent,
        name: &str,
        args: &serde_json::Value,
    ) -> Result<(), SessionError> {
        self.current()?;
        self.base.authorize_tool(intent, name, args)
    }
    fn child_authority(
        &self,
        target: &str,
        stream: &SessionStreamId,
    ) -> Result<Arc<dyn EngineSessionAuthority>, SessionError> {
        self.current()?;
        Ok(Arc::new(Self {
            base: self.base.child_authority(target, stream)?,
            capability: self.capability.clone(),
            sender: self.sender.clone(),
            recipient: self.recipient.clone(),
            channel: self.channel.clone(),
        }))
    }
}
impl EngineSessionAuthority for PeerAuthority {
    fn execution_binding(&self, input: &EngineTurnInput) -> Result<PayloadRecord, SessionError> {
        self.current()?;
        self.base.execution_binding(input)
    }
    fn maintenance_binding(&self) -> Result<PayloadRecord, SessionError> {
        self.current()?;
        self.base.maintenance_binding()
    }
    fn classify_text(&self, text: &str) -> String {
        self.base.classify_text(text)
    }
    fn diagnostic(&self, error: &anyhow::Error) -> Option<String> {
        self.base.diagnostic(error)
    }
}

pub(super) async fn open(
    source: Arc<dyn EngineSessionSource>,
    admission: AgentExecutionAdmission,
    task: &str,
    sender: &str,
    recipient: &str,
    channel: &str,
) -> anyhow::Result<Arc<dyn SessionExecutionPort>> {
    let family = format!("peer-inbox:{task}");
    let capability = admission.capability();
    let base = Arc::new(crate::live_config_authority::AgentHistoryAuthority {
        admission,
        actor: EventActor::System {
            component: "peer_inbox".into(),
        },
        stream: source.stream_id(&family).await?,
        origin: zeroclaw_api::ingress::TurnOrigin::AgentDirect,
        parent_alias: None,
    });
    let authority = Arc::new(PeerAuthority {
        base,
        capability,
        sender: sender.into(),
        recipient: recipient.into(),
        channel: channel.into(),
    });
    source
        .open_system(
            family,
            recipient.into(),
            "peer_inbox".into(),
            authority,
            ContextSnapshot {
                messages: vec![],
                history_has_trim_breadcrumb: Some(false),
            },
        )
        .await
}
