// static/chat.js - Chat functionality

class ChatManager {
    constructor(conversationId, currentUserId, otherUserId, otherUsername, csrfToken) {
        this.conversationId = conversationId;
        this.currentUserId = currentUserId;
        this.otherUserId = otherUserId;
        this.otherUsername = otherUsername;
        this.csrfToken = csrfToken;
        this.ws = null;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
        this.userScrolledUp = false;
        this.lastScrollTop = 0;
        this.typingTimeout = null;
        this.currentMessageIdForReaction = null;
        this.maxChars = 0;
        
        this.init();
    }
    
    init() {
        this.chatMessages = document.getElementById('chatMessages');
        this.messageInput = document.getElementById('messageInput');
        this.sendBtn = document.getElementById('sendBtn');
        this.charCounterSpan = document.getElementById('charCounter');
        this.statusDot = document.getElementById('statusDot');
        this.statusText = document.getElementById('statusText');
        
        if (!this.chatMessages) return;
        
        const maxCharsSpan = document.getElementById('maxChars');
        if (maxCharsSpan) {
            const maxCharsText = maxCharsSpan.textContent;
            if (maxCharsText === 'Unlimited') {
                this.maxChars = 999999;
            } else {
                this.maxChars = parseInt(maxCharsText, 10);
            }
        }
        
        this.setupEventListeners();
        this.connectWebSocket();
        this.updateExpiryTimers();
        setInterval(() => this.updateExpiryTimers(), 1000);
        if (this.messageInput) this.updateCharCounter();
        
        this.chatMessages.scrollTop = this.chatMessages.scrollHeight;
    }
    
    setupEventListeners() {
        if (this.chatMessages) {
            this.chatMessages.addEventListener('scroll', () => this.handleScroll());
        }
        
        if (this.messageInput) {
            this.messageInput.addEventListener('input', () => {
                this.updateCharCounter();
                this.sendTypingIndicator();
            });
            this.messageInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    this.sendMessage();
                }
            });
        }
        
        if (this.sendBtn) {
            this.sendBtn.addEventListener('click', () => this.sendMessage());
        }
    }
    
    handleScroll() {
        const isAtBottom = this.isScrolledToBottom();
        if (isAtBottom) {
            this.userScrolledUp = false;
        } else {
            if (this.chatMessages.scrollTop < this.lastScrollTop) {
                this.userScrolledUp = true;
            }
        }
        this.lastScrollTop = this.chatMessages.scrollTop;
    }
    
    isScrolledToBottom() {
        const threshold = 100;
        const position = this.chatMessages.scrollTop + this.chatMessages.clientHeight;
        const height = this.chatMessages.scrollHeight;
        return position >= height - threshold;
    }
    
    scrollToBottomIfNeeded() {
        if (!this.userScrolledUp && this.chatMessages) {
            this.chatMessages.scrollTop = this.chatMessages.scrollHeight;
        }
    }
    
    updateCharCounter() {
        if (!this.messageInput || !this.charCounterSpan) return;
        const length = this.messageInput.value.length;
        if (this.maxChars === 999999) {
            this.charCounterSpan.textContent = length + ' / Unlimited';
        } else {
            this.charCounterSpan.textContent = length + ' / ' + this.maxChars;
        }
        if (length > this.maxChars && this.maxChars !== 999999) {
            this.messageInput.value = this.messageInput.value.substring(0, this.maxChars);
            this.updateCharCounter();
        }
    }
    
    sendTypingIndicator() {
        if (this.typingTimeout) clearTimeout(this.typingTimeout);
        
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            this.ws.send(JSON.stringify({ type: 'typing', is_typing: true }));
        }
        
        this.typingTimeout = setTimeout(() => {
            if (this.ws && this.ws.readyState === WebSocket.OPEN) {
                this.ws.send(JSON.stringify({ type: 'typing', is_typing: false }));
            }
        }, 2000);
    }
    
    showTypingIndicator(username) {
        const existingIndicator = document.querySelector('.typing-indicator');
        if (existingIndicator) existingIndicator.remove();
        
        const indicator = document.createElement('div');
        indicator.className = 'typing-indicator message-received';
        indicator.style.padding = '0.5rem 1rem';
        indicator.style.fontSize = '0.75rem';
        indicator.style.fontStyle = 'italic';
        indicator.textContent = username + ' is typing...';
        this.chatMessages.appendChild(indicator);
        this.scrollToBottomIfNeeded();
        
        setTimeout(() => {
            if (indicator.parentNode) indicator.remove();
        }, 3000);
    }
    
    connectWebSocket() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/chat/ws/${this.conversationId}`;
        
        this.ws = new WebSocket(wsUrl);
        
        this.ws.onopen = () => {
            this.reconnectAttempts = 0;
        };
        
        this.ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            this.handleWebSocketMessage(data);
        };
        
        this.ws.onclose = () => {
            this.updateUserStatus('offline');
            if (this.reconnectAttempts < this.maxReconnectAttempts) {
                this.reconnectAttempts++;
                setTimeout(() => this.connectWebSocket(), 3000);
            }
        };
    }
    
    handleWebSocketMessage(data) {
        if (data.type === 'new_message') {
            this.addMessageToChat(data.message, data.message.sender_id === this.currentUserId);
            this.scrollToBottomIfNeeded();
        } else if (data.type === 'message_sent') {
            const tempDiv = document.querySelector('.message[data-message-id="temp"]');
            if (tempDiv) {
                tempDiv.setAttribute('data-message-id', data.message.id);
                const statusSpan = tempDiv.querySelector('.message-status');
                if (statusSpan) statusSpan.textContent = 'Sent';
            }
        } else if (data.type === 'message_read') {
            const messageDiv = document.querySelector(`.message[data-message-id="${data.message_id}"]`);
            if (messageDiv) {
                const statusSpan = messageDiv.querySelector('.message-status');
                if (statusSpan) statusSpan.textContent = 'Read';
            }
        } else if (data.type === 'status') {
            this.updateUserStatus(data.status);
        } else if (data.type === 'typing') {
            this.showTypingIndicator(data.username);
        }
    }
    
    updateUserStatus(status) {
        if (!this.statusDot || !this.statusText) return;
        if (status === 'online') {
            this.statusDot.className = 'status-dot online';
            this.statusText.textContent = 'Online';
        } else {
            this.statusDot.className = 'status-dot offline';
            this.statusText.textContent = 'Offline';
        }
    }
    
    escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
    
    addMessageToChat(message, isSentByCurrentUser) {
        const messageDiv = document.createElement('div');
        messageDiv.className = 'message ' + (isSentByCurrentUser ? 'message-sent' : 'message-received');
        messageDiv.setAttribute('data-message-id', message.id || 'temp');
        const timeStr = new Date(message.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        messageDiv.innerHTML = `
            <div class="message-content">${this.escapeHtml(message.content)}</div>
            <div class="message-footer">
                <span class="message-time">${timeStr}</span>
                <span class="message-status">${isSentByCurrentUser ? 'Sent' : ''}</span>
                <button class="reaction-trigger" data-message-id="${message.id || 'temp'}">[React]</button>
                <span class="message-expiry" data-expires="${message.expires_at}"></span>
            </div>
        `;
        this.chatMessages.appendChild(messageDiv);
        
        const trigger = messageDiv.querySelector('.reaction-trigger');
        if (trigger) {
            trigger.addEventListener('click', () => this.showReactionModal(trigger.dataset.messageId));
        }
        
        this.updateExpiryTimers();
        
        if (!isSentByCurrentUser && message.id !== 'temp') {
            fetch(`/chat/mark_read/${message.id}`, { method: 'POST' });
        }
    }
    
    updateExpiryTimers() {
        const expirySpans = document.querySelectorAll('.message-expiry');
        const now = new Date();
        expirySpans.forEach(span => {
            const expiryTime = new Date(span.dataset.expires);
            const diff = expiryTime - now;
            if (diff <= 0) {
                span.textContent = '[Expired]';
                span.closest('.message').style.opacity = '0.5';
            } else {
                const hours = Math.floor(diff / 3600000);
                const minutes = Math.floor((diff % 3600000) / 60000);
                span.textContent = `Expires in: ${hours}h ${minutes}m`;
            }
        });
    }
    
    sendMessage() {
        if (!this.messageInput) return;
        const content = this.messageInput.value.trim();
        if (!content) return;
        if (content.length > this.maxChars && this.maxChars !== 999999) {
            if (window.toast) window.toast.error('Message exceeds character limit');
            return;
        }
        
        const tempMessage = {
            id: 'temp',
            content: content,
            created_at: new Date().toISOString(),
            expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString()
        };
        
        this.addMessageToChat(tempMessage, true);
        this.messageInput.value = '';
        this.updateCharCounter();
        this.scrollToBottomIfNeeded();
        
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            this.ws.send(JSON.stringify({ type: 'message', content: content }));
        } else {
            const formData = new FormData();
            formData.append('recipient_id', this.otherUserId);
            formData.append('content', content);
            formData.append('csrf_token', this.csrfToken);
            
            fetch('/chat/send', {
                method: 'POST',
                body: formData
            })
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    const tempDiv = document.querySelector('.message[data-message-id="temp"]');
                    if (tempDiv) {
                        tempDiv.setAttribute('data-message-id', data.message.id);
                        const statusSpan = tempDiv.querySelector('.message-status');
                        if (statusSpan) statusSpan.textContent = 'Sent';
                    }
                } else {
                    if (window.toast) window.toast.error('Error: ' + this.escapeHtml(data.error));
                    const tempDiv = document.querySelector('.message[data-message-id="temp"]');
                    if (tempDiv) tempDiv.remove();
                }
            })
            .catch(err => {
                if (window.toast) window.toast.error('Error sending message: ' + this.escapeHtml(err.message));
                const tempDiv = document.querySelector('.message[data-message-id="temp"]');
                if (tempDiv) tempDiv.remove();
            });
        }
    }
    
    showReactionModal(messageId) {
        this.currentMessageIdForReaction = messageId;
        const modal = document.getElementById('reactionModal');
        if (modal) modal.style.display = 'block';
        
        document.querySelectorAll('.reaction-option').forEach(btn => {
            btn.onclick = () => {
                const reactionType = btn.dataset.reaction;
                this.addReaction(this.currentMessageIdForReaction, reactionType);
                this.closeReactionModal();
            };
        });
    }
    
    closeReactionModal() {
        const modal = document.getElementById('reactionModal');
        if (modal) modal.style.display = 'none';
        this.currentMessageIdForReaction = null;
    }
    
    addReaction(messageId, reactionType) {
        if (window.toast) window.toast.info('Reactions coming soon for private chats');
        this.closeReactionModal();
    }
    
    blockUser() {
        if (confirm('Block ' + this.otherUsername + '? You will no longer receive messages from this user.')) {
            fetch('/chat/block/' + this.otherUserId, { method: 'POST' })
                .then(res => res.json())
                .then(data => {
                    if (data.success) {
                        if (window.toast) window.toast.success('User blocked successfully');
                        location.reload();
                    } else {
                        if (window.toast) window.toast.error(this.escapeHtml(data.error || 'Failed to block user'));
                    }
                });
        }
    }
    
    unblockUser() {
        if (confirm('Unblock ' + this.otherUsername + '? You will be able to send messages again.')) {
            fetch('/chat/unblock/' + this.otherUserId, { method: 'POST' })
                .then(res => res.json())
                .then(data => {
                    if (data.success) {
                        if (window.toast) window.toast.success('User unblocked successfully');
                        location.reload();
                    } else {
                        if (window.toast) window.toast.error(this.escapeHtml(data.error || 'Failed to unblock user'));
                    }
                });
        }
    }
}

// Initialize chat when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    const chatContainer = document.getElementById('chatContainer');
    if (chatContainer && chatContainer.dataset.conversationId) {
        window.chatManager = new ChatManager(
            parseInt(chatContainer.dataset.conversationId, 10),
            parseInt(chatContainer.dataset.currentUserId, 10),
            parseInt(chatContainer.dataset.otherUserId, 10),
            chatContainer.dataset.otherUsername,
            chatContainer.dataset.csrfToken
        );
    }
});
