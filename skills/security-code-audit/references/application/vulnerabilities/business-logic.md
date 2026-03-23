# Business Logic Vulnerabilities

## Negative Value Attacks

Attackers pass negative numbers where only positive values are expected, reversing the direction of operations.

### Negative Transfer Amounts

**Python - VULNERABLE:**
```python
def transfer(request):
    amount = Decimal(request.POST['amount'])
    sender = Account.objects.select_for_update().get(id=request.user.id)
    recipient = Account.objects.select_for_update().get(id=request.POST['to'])
    if sender.balance >= amount:  # -500 >= anything passes if balance > -500
        sender.balance -= amount  # -= (-500) => balance INCREASES
        recipient.balance += amount  # += (-500) => victim loses money
        sender.save()
        recipient.save()
```

**Python - FIXED:**
```python
def transfer(request):
    amount = Decimal(request.POST['amount'])
    if amount <= 0:
        raise ValidationError("Amount must be positive")
    if amount > Decimal('1000000'):  # Upper bound too
        raise ValidationError("Amount exceeds maximum")
    # ... proceed with validated amount
```

### Negative Quantities in Orders

**JavaScript - VULNERABLE:**
```javascript
app.post('/cart/add', (req, res) => {
  const { productId, quantity } = req.body;
  const product = await Product.findById(productId);
  const lineTotal = product.price * quantity; // price=50 * quantity=-3 = -150
  cart.items.push({ productId, quantity, lineTotal });
  cart.total += lineTotal; // total decreases
});
```

**JavaScript - FIXED:**
```javascript
app.post('/cart/add', (req, res) => {
  const quantity = parseInt(req.body.quantity, 10);
  if (!Number.isInteger(quantity) || quantity < 1 || quantity > 999) {
    return res.status(400).json({ error: 'Invalid quantity' });
  }
  const product = await Product.findById(req.body.productId);
  const lineTotal = product.price * quantity; // Server-side calculation only
  // ...
});
```

### Negative Discount / Refund Abuse

**Java - VULNERABLE:**
```java
@PostMapping("/refund")
public ResponseEntity<?> processRefund(@RequestBody RefundRequest req) {
    // No validation that amount is positive and <= original charge
    BigDecimal refundAmount = req.getAmount();
    account.setBalance(account.getBalance().add(refundAmount));
    // Passing negative refundAmount would deduct from account
    // Passing amount > original charge is also abuse
    accountRepo.save(account);
    return ResponseEntity.ok("Refunded");
}
```

---

## Mass Assignment

User-controlled JSON keys are mapped directly to model fields, allowing attackers to set fields they should not control.

### Role Escalation via Registration

**JavaScript (Express + Mongoose) - VULNERABLE:**
```javascript
app.post('/register', async (req, res) => {
  const user = new User(req.body);
  // req.body = { email: "a@b.com", password: "x", role: "admin" }
  await user.save();
});
```

**JavaScript - FIXED with allowlist:**
```javascript
app.post('/register', async (req, res) => {
  const user = new User({
    email: req.body.email,
    password: req.body.password,
    name: req.body.name,
    // role is NOT copied from input; defaults to 'user'
  });
  await user.save();
});
```

### Price / Rate Override

**Python (Django REST Framework) - VULNERABLE:**
```python
class OrderSerializer(serializers.ModelSerializer):
    class Meta:
        model = Order
        fields = '__all__'  # Includes price, discount, tax_rate, exchange_rate
```

**Python - FIXED:**
```python
class OrderSerializer(serializers.ModelSerializer):
    class Meta:
        model = Order
        fields = ['product_id', 'quantity', 'shipping_address']
        read_only_fields = ['price', 'discount', 'tax_rate', 'total', 'exchange_rate']
```

### Java Spring - Mass Assignment

**VULNERABLE:**
```java
@PostMapping("/profile")
public ResponseEntity<?> updateProfile(@RequestBody User user) {
    // Attacker sends: {"name":"John", "role":"ADMIN", "accountBalance": 999999}
    userRepository.save(user);
    return ResponseEntity.ok("Updated");
}
```

**FIXED with DTO:**
```java
public class ProfileUpdateDTO {
    private String name;
    private String email;
    private String phone;
    // No role, no balance, no id fields
}

@PostMapping("/profile")
public ResponseEntity<?> updateProfile(@RequestBody ProfileUpdateDTO dto) {
    User user = userRepository.findById(getCurrentUserId()).orElseThrow();
    user.setName(dto.getName());
    user.setEmail(dto.getEmail());
    user.setPhone(dto.getPhone());
    userRepository.save(user);
    return ResponseEntity.ok("Updated");
}
```

### Go - Mass Assignment

**VULNERABLE:**
```go
func UpdateUser(c *gin.Context) {
    var user models.User
    if err := c.ShouldBindJSON(&user); err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }
    // Attacker controls all fields including Role, IsAdmin, Balance
    db.Save(&user)
}
```

**FIXED:**
```go
type UpdateProfileRequest struct {
    Name  string `json:"name" binding:"required"`
    Email string `json:"email" binding:"required,email"`
    Phone string `json:"phone"`
}

func UpdateUser(c *gin.Context) {
    var req UpdateProfileRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }
    userID := c.GetInt("userID") // From auth middleware
    db.Model(&models.User{}).Where("id = ?", userID).Updates(map[string]interface{}{
        "name":  req.Name,
        "email": req.Email,
        "phone": req.Phone,
    })
}
```

---

## State Machine Violations

### Skipping Workflow Steps

**Python - VULNERABLE:**
```python
# Order states: created -> paid -> shipped -> delivered
def ship_order(request, order_id):
    order = Order.objects.get(id=order_id)
    # Missing: check that order.status == 'paid'
    order.status = 'shipped'
    order.save()
    # Attacker ships an unpaid order
```

**Python - FIXED with explicit state transitions:**
```python
VALID_TRANSITIONS = {
    'created': ['paid', 'cancelled'],
    'paid': ['shipped', 'refunded'],
    'shipped': ['delivered', 'returned'],
    'delivered': [],
    'cancelled': [],
    'refunded': [],
}

def transition_order(order, new_status, actor):
    if new_status not in VALID_TRANSITIONS.get(order.status, []):
        raise InvalidTransition(
            f"Cannot transition from {order.status} to {new_status}"
        )
    old_status = order.status
    order.status = new_status
    order.save()
    AuditLog.objects.create(
        order=order, from_status=old_status,
        to_status=new_status, actor=actor
    )
```

### Replaying Completed Actions

**JavaScript - VULNERABLE:**
```javascript
app.post('/claim-reward', async (req, res) => {
  const quest = await Quest.findById(req.body.questId);
  if (quest.completed) {
    await grantReward(req.user.id, quest.reward);
    // No flag set to prevent re-claiming
    res.json({ success: true });
  }
});
```

**JavaScript - FIXED:**
```javascript
app.post('/claim-reward', async (req, res) => {
  const result = await Quest.findOneAndUpdate(
    {
      _id: req.body.questId,
      userId: req.user.id,
      completed: true,
      rewardClaimed: false  // Atomic check
    },
    { $set: { rewardClaimed: true, rewardClaimedAt: new Date() } },
    { new: true }
  );
  if (!result) {
    return res.status(400).json({ error: 'Reward already claimed or quest not completed' });
  }
  await grantReward(req.user.id, result.reward);
  res.json({ success: true });
});
```

---

## Financial Calculation Manipulation

### Client-Controlled Prices / Rates

**VULNERABLE patterns to look for:**
```javascript
// Client sends final price
app.post('/checkout', (req, res) => {
  const { items, total } = req.body;
  // Using client-provided total instead of recalculating server-side
  charge(req.user, total);
});

// Client sends discount percentage
app.post('/apply-discount', (req, res) => {
  const { discountPercent } = req.body; // attacker sends 100
  order.total *= (1 - discountPercent / 100);
});

// Client sends exchange rate
app.post('/convert', (req, res) => {
  const { amount, exchangeRate } = req.body;
  const converted = amount * exchangeRate; // attacker controls rate
});
```

**FIXED: Always compute on server side:**
```javascript
app.post('/checkout', async (req, res) => {
  const { items } = req.body;
  // Recalculate everything server-side from source of truth
  let total = 0;
  for (const item of items) {
    const product = await Product.findById(item.productId);
    if (!product) throw new Error('Invalid product');
    total += product.price * item.quantity; // Server-side price lookup
  }
  const discount = await calculateDiscount(req.user.id); // Server-side rules
  const tax = calculateTax(total - discount, req.user.region); // Server-side
  const finalTotal = total - discount + tax;
  charge(req.user, finalTotal);
});
```

### Rounding Errors

**Python - VULNERABLE:**
```python
# Floating point: 0.1 + 0.2 != 0.3
price = 19.99
tax_rate = 0.0725
tax = price * tax_rate  # 1.449275 - rounds unpredictably
```

**Python - FIXED:**
```python
from decimal import Decimal, ROUND_HALF_UP

price = Decimal('19.99')
tax_rate = Decimal('0.0725')
tax = (price * tax_rate).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
# 1.45 - deterministic
```

---

## Quota / Limit Bypass

### Parameter Manipulation

**VULNERABLE:**
```python
# API returns paginated results, client controls page_size
def list_items(request):
    page_size = int(request.GET.get('page_size', 20))
    # Attacker: ?page_size=999999 => dumps entire DB
    items = Item.objects.all()[:page_size]
```

**FIXED:**
```python
def list_items(request):
    page_size = min(int(request.GET.get('page_size', 20)), 100)  # Cap at 100
    items = Item.objects.all()[:page_size]
```

### Trial / Free Tier Abuse

**VULNERABLE:**
```python
def create_project(request):
    user = request.user
    plan = user.subscription_plan  # Could be manipulated via mass assignment
    if plan == 'free':
        limit = 5
    elif plan == 'pro':
        limit = 100
    # Attacker changes plan field via another endpoint's mass assignment
```

**FIXED: Derive limits from authoritative source:**
```python
def create_project(request):
    subscription = Subscription.objects.get(
        user=request.user, status='active'
    )
    plan_limits = PLAN_LIMITS[subscription.plan_id]  # Server-side lookup table
    current_count = Project.objects.filter(owner=request.user).count()
    if current_count >= plan_limits['max_projects']:
        raise QuotaExceeded()
```

---

## Multi-Step Process Abuse

### Password Reset Flow

**VULNERABLE:**
```python
# Step 1: Request reset (sends email with token)
def request_reset(email):
    token = generate_token()
    ResetToken.objects.create(user=user, token=token)
    send_email(email, token)

# Step 2: Verify token
def verify_token(request):
    token = ResetToken.objects.get(token=request.POST['token'])
    request.session['reset_user_id'] = token.user_id
    # Token not invalidated after verification

# Step 3: Set new password
def set_password(request):
    user_id = request.session.get('reset_user_id')
    # Attacker: complete step 2 for victim, then change own password target
    user = User.objects.get(id=user_id)
    user.set_password(request.POST['password'])
    user.save()
```

**FIXED:**
```python
def set_password(request):
    token = request.POST.get('token')  # Require token again
    reset = ResetToken.objects.get(
        token=token,
        used=False,
        created_at__gte=timezone.now() - timedelta(hours=1)
    )
    reset.user.set_password(request.POST['password'])
    reset.user.save()
    reset.used = True  # Invalidate token
    reset.save()
    ResetToken.objects.filter(user=reset.user, used=False).update(used=True)
```

### Checkout Flow Manipulation

**VULNERABLE:**
```
Step 1: Add items to cart
Step 2: Enter shipping address
Step 3: Select payment method
Step 4: Confirm order -> charges payment

Attack: Complete steps 1-3, modify cart contents (step 1) via API,
then hit confirm (step 4). Price shown at step 3 != actual charge.
```

**FIXED: Recalculate at every step and lock at confirmation:**
```python
def confirm_order(request):
    cart = Cart.objects.select_for_update().get(user=request.user)
    # Recalculate from source of truth
    recalculated_total = sum(
        item.product.current_price * item.quantity
        for item in cart.items.select_related('product')
    )
    if recalculated_total != cart.displayed_total:
        return JsonResponse({
            'error': 'Cart has changed',
            'new_total': str(recalculated_total)
        }, status=409)
    # Proceed with charge
```

---

## Detection Methodology

### Actor x Action x Resource Matrix

Map every API endpoint to this matrix and look for missing authorization checks:

| Actor | Action | Resource | Auth Check? |
|---|---|---|---|
| Regular user | View | Own profile | Yes |
| Regular user | View | Other user profile | ? |
| Regular user | Edit | Own profile | Yes |
| Regular user | Edit | Other user profile | ? |
| Regular user | Delete | Own account | Yes |
| Regular user | Delete | Other account | ? |
| Regular user | Access | Admin panel | ? |
| Unauthenticated | Access | Any protected resource | ? |

### Invariant Validation Checklist

For every financial/stateful operation, verify these invariants:
1. **Amounts are always positive** (or explicitly handle negatives)
2. **Sum of all accounts = constant** (money is neither created nor destroyed)
3. **State transitions follow defined paths** (no skipping steps)
4. **Server-side values match client-side values** (prices, rates, totals)
5. **Operations are idempotent** (same request twice = same result)
6. **Counts/quotas are enforced atomically** (not check-then-act)

---

## Grep Patterns for Business Logic Flaws

```bash
# Negative value: missing validation on numeric inputs
grep -rn 'amount\|price\|quantity\|total\|balance\|credits' --include='*.py' --include='*.js' --include='*.java' --include='*.go' | grep -iv 'if.*> 0\|if.*<= 0\|if.*>=.*0\|positive\|negative\|min(\|Min(\|minimum'

# Mass assignment: entire request body passed to model
grep -rn 'req\.body\|request\.POST\|request\.data' --include='*.py' --include='*.js' --include='*.ts' | grep -i 'create\|update\|save\|new '
grep -rn "fields.*=.*'__all__'" --include='*.py'
grep -rn '@RequestBody.*User\|@RequestBody.*Account\|@RequestBody.*Order' --include='*.java'

# Client-controlled prices/rates
grep -rn 'price\|rate\|discount\|fee\|tax\|total\|exchange' --include='*.py' --include='*.js' | grep -i 'req\.\|request\.\|params\.\|body\.'

# Missing state checks before transitions
grep -rn "status.*=.*'shipped'\|status.*=.*'approved'\|status.*=.*'completed'" --include='*.py' --include='*.js' | grep -v 'if.*status'

# Uncapped pagination
grep -rn 'page_size\|pageSize\|per_page\|perPage\|limit' --include='*.py' --include='*.js' --include='*.java' | grep -i 'request\|req\|param' | grep -v 'min(\|Max\.\|Math\.min\|max.*='

# Token/code reuse (not invalidated after use)
grep -rn 'token\|code\|otp\|reset' --include='*.py' --include='*.js' | grep -i 'verify\|validate\|check' | grep -v 'used\|invalidat\|delet\|expir'

# Server trusting client-computed values
grep -rn 'total\|subtotal\|grand_total\|final_price' --include='*.py' --include='*.js' | grep -i 'req\.\|request\.\|body\.'
```
